"""One outbound-HTTP policy for the copilot's side-effect channels.

Elastic, TheHive and the webhook each hand-rolled the same client
handling — owned-vs-injected client, raise_for_status, domain error
translation — with NO retry anywhere. For a loop meant to run unattended
that made every transient blip expensive: a refused connection during an
Elastic push costs a full re-investigation next cycle (the model call is
the expensive part, and it had already succeeded); a TheHive restart
loses a case; a webhook hiccup loses the one 03:00 page the channel
exists for. This module is the single place the outbound policy lives,
so "how does this project retry?" has exactly one answer.

The policy, deliberately small:

- ONE retry, after a short fixed backoff. Bounded by design — an outage
  is the poll loop's problem (it already retries whole cycles); this
  only papers over the single-blip failures where a second attempt a
  second later succeeds.
- A CONNECT failure (refused, unreachable, connect timeout) is ALWAYS
  retried: the request never reached the server, so replaying it cannot
  double-apply anything.
- Anything after the request may have reached the server — a 429/502/
  503/504 response, a read timeout — is retried only when the caller
  declared the request `replayable`. That flag is a per-call-site
  statement that applying the request twice is acceptable: searches and
  fixed-value updates are; indexing a fresh `_doc` (a duplicate results
  row) and creating a TheHive alert are not. Naming it `replayable`
  rather than `idempotent` is deliberate — the webhook page is not
  idempotent, but a duplicate page beats a lost one, and the flag says
  exactly that and no more.
- Response errors outside {429, 502, 503, 504} never retry: a 400 or a
  403 will not get better by asking again.

Callers keep their own error translation: this module raises the same
httpx exceptions single-shot code did, just after the policy is spent.
"""
import asyncio

import httpx

# One retry: enough for a blip, bounded for an outage.
RETRIES = 1
BACKOFF_SECONDS = 1.0
# The transient trio (gateway hiccups) plus explicit throttling. 500 is
# deliberately absent: an unhandled server error is not known-transient.
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})


async def request(
    method: str,
    url: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 20.0,
    replayable: bool = False,
    **kwargs,
) -> httpx.Response:
    """Send one HTTP request under the project's retry policy.

    `client=None` (production) opens and closes a client per call, as
    every channel already did; tests inject a MockTransport-backed
    client, which also bypasses `timeout` (the injected client's own
    config wins, matching the previous per-channel behavior).
    Raises httpx.HTTPStatusError on a non-2xx final answer, or the
    underlying httpx error when transport fails past the policy.
    """

    async def attempt(c: httpx.AsyncClient) -> httpx.Response:
        for tries_left in range(RETRIES, -1, -1):
            try:
                resp = await c.request(method, url, **kwargs)
                resp.raise_for_status()
                return resp
            except (httpx.ConnectError, httpx.ConnectTimeout):
                # Never reached the server: always safe to replay.
                if not tries_left:
                    raise
            except httpx.HTTPStatusError as e:
                if (
                    not tries_left
                    or not replayable
                    or e.response.status_code not in RETRYABLE_STATUS
                ):
                    raise
            except httpx.HTTPError:
                # Read timeout, dropped connection mid-response, protocol
                # error: the server may have processed the request.
                if not tries_left or not replayable:
                    raise
            await asyncio.sleep(BACKOFF_SECONDS)
        raise AssertionError("unreachable: loop returns or raises")

    if client is not None:
        return await attempt(client)
    async with httpx.AsyncClient(timeout=timeout) as owned:
        return await attempt(owned)
