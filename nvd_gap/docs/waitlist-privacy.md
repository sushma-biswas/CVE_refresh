# Waitlist data protection design

Design for collecting email addresses for the change-feed waitlist, written
against GDPR and the ePrivacy Directive. Not legal advice — this is an
engineering design, and a real list is worth a short review by someone
qualified before it goes live.

`[JURISDICTION]` below must be replaced with the EU member state of
establishment. It decides the competent supervisory authority and a few
specifics.

## Where the addresses go

**They are never stored by us.** A hosted email provider is both the store and
the processor; we hold no addresses in our own infrastructure, our own
database, or the repository.

Rejected alternatives, and why:

| Option | Why not |
|---|---|
| Artifact `db` capability | Returns `null` for anyone not signed in to claude.ai, so a public visitor gets a dead form. Shared docs are readable by signed-in viewers; the only private path is private from the owner too. No unsubscribe, no suppression list, no DPA. |
| Our own Worker + database | Makes us sole controller *and* processor. We would have to build double opt-in, the unsubscribe endpoint, the suppression list, and export/erasure handling, and carry the breach liability. Disproportionate for a demand test. |
| A form POSTing to a provider's API from a static page | Requires an API key in client-side code. Never do this. |

**The provider must supply all of:** a Data Processing Agreement under Art. 28,
EU/EEA hosting or a documented Art. 46 transfer safeguard, double opt-in,
one-click unsubscribe with `List-Unsubscribe` headers, a suppression list, and
data export plus deletion on request. Buttondown and beehiiv both meet this on
free or low tiers; confirm the DPA is actually signable before committing.

The capture page itself is static hosting (Cloudflare Pages) carrying the
pitch, the short notice, and a link to the provider's hosted signup form. No
form handling of our own means no personal data in transit through anything we
operate.

## Lawful basis: consent

**Consent**, Art. 6(1)(a), reinforced by ePrivacy Directive Art. 13.

Not legitimate interest. ePrivacy requires prior consent for unsolicited
commercial email to individuals, and the soft opt-in exception needs an
existing customer relationship for similar products — which does not exist for
a waitlist. Legitimate interest is not available here however it is argued.

Consent must be freely given, specific, informed, unambiguous, and given by
affirmative action. That means:

- No pre-ticked boxes, and no consent inferred from using the site.
- Not bundled with anything else. One purpose, stated plainly.
- The waitlist is not a condition of reading the dashboard — the dashboard
  stays fully usable without signing up.

### Proving it

Art. 7(1) requires us to be able to *demonstrate* consent. **Use double
opt-in**, which both proves consent and stops anyone entering someone else's
address. The provider must record, per subscriber:

- the address
- signup timestamp and IP
- confirmation timestamp and IP
- the version identifier of the notice text shown at signup

That last field matters and is easy to forget: if the wording changes, we must
still know what each person actually agreed to. Keep each version of the notice
text in this repository so the identifier resolves to real text.

## Privacy notice

Layered: a short notice at the point of collection, with the full notice one
click away. The short form, beside the field:

> Your address is used only to tell you when the change feed launches —
> nothing else, and never shared. One email, maybe two. Unsubscribe in one
> click from any of them, or withdraw consent at any time. Stored by
> [PROVIDER] on our behalf. [Full privacy notice]

The full notice must state all of the following (Art. 13):

1. **Controller identity and contact details.** A reachable name and email
   address. See the tension noted below.
2. **Purpose**: to notify you when the CVE change feed launches.
3. **Lawful basis**: your consent.
4. **Processor**: [PROVIDER], named, with its role described.
5. **Transfers outside the EEA**, if any, and the Art. 46 safeguard relied on
   (Standard Contractual Clauses, or the EU–US Data Privacy Framework where the
   provider is certified).
6. **Retention**: deleted if the feed has not launched within 12 months, or
   within 30 days of unsubscribing, whichever comes first.
7. **Rights**: access, rectification, erasure, restriction, objection,
   portability; withdraw consent at any time; lodge a complaint with the
   supervisory authority of [JURISDICTION].
8. **That providing the address is voluntary**, and nothing is withheld if you
   do not.
9. **No automated decision-making and no profiling** take place.

### One real tension

A controller must be identifiable and reachable. That is incompatible with
running this project pseudonymously. Either a real name and contact address go
on the notice, or an entity is registered to be the controller instead. There
is no third option that is both anonymous and lawful — so if the brand is
meant to carry the project rather than a person, that decision has to be made
before the first address is collected, not after.

## Unsubscribe

Withdrawal must be as easy as giving consent (Art. 7(3)), which rules out
anything requiring a login or a reply.

- **One-click link in every email**, no authentication, no confirmation step.
- **`List-Unsubscribe` and `List-Unsubscribe-Post` headers** (RFC 8058) on
  every send. Beyond the legal requirement, Gmail and Yahoo bulk-sender rules
  make these a practical condition of being delivered at all.
- **A withdrawal path that is not an email**: a link on the capture page, for
  someone who wants out without finding a message to click.
- **Honour promptly**, and move the address to the provider's suppression list
  rather than deleting the row, so a later import cannot re-add it. An erasure
  request under Art. 17 is different and does delete — the suppression entry
  then keeps only a hash, not the address.
- **Confirm on screen**, not by sending another email.

## What this does not cover

Analytics on the dashboard or capture page. If anything beyond strictly
necessary cookies is ever added, that needs its own consent mechanism under
ePrivacy Art. 5(3), and a cookie banner is then unavoidable. Keeping analytics
cookieless (or absent) avoids the banner entirely, which is the better outcome
for a page whose credibility is the product.
