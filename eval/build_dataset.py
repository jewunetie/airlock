#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Build the airlock guard evaluation set.

Emits eval/dataset.jsonl: 320 records, 8 categories, 20 block and 20 approve
in each. Every example is synthetic. No text here is drawn from real user
data, real documents, or any private folder.

Synthetic values use reserved or well-known test ranges wherever one exists,
so that nothing in this file can collide with a real identifier:

    phone       555-01xx, reserved for fiction (NANP)
    email       @example.com and @example.org (RFC 2606)
    credit card 4111 1111 1111 1111, the standard Visa test number
    domains     example.com, example.net (RFC 2606)

Social security numbers, routing numbers, account numbers, medical record
numbers and case numbers have no reserved test range. Those are format-valid
inventions chosen to avoid published real values.

Credentials have no reserved test range either, and a fixed fabricated one is
worse than an invented SSN: GitHub's secret scanning matches vendor key
SHAPES, not "is this real", and a hand-picked fake stripe key once got this
repository's push rejected for looking close enough to a live one (see
CLAUDE.md). So credential examples are generated at run time from a real
vendor prefix plus a random body, the same approach tests/test_server.py uses
for fake_credential and CREDENTIAL_SHAPES: nothing that could pass for a real
key is ever a literal in this file. Generation is seeded (--seed, a fixed
default) so the emitted dataset is identical across runs and the reported
category counts stay reproducible.

A caveat that matters for reading the results. The Privacy Filter model card
warns of "over-redaction of benign high-entropy strings, placeholders, hashes,
sample credentials, or synthetic examples that resemble secrets." A synthetic
eval set is therefore biased against Privacy Filter on the credential
categories specifically. Treat category 6 false positives as an upper bound,
not as a field estimate.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import string
from pathlib import Path

# Each entry: (text, expected_findings, notes)
# gold_label is implied by which list it appears in.

ALNUM = string.ascii_letters + string.digits
HEXLOWER = string.digits + "abcdef"
B64 = ALNUM + "+/"

DEFAULT_SEED = 20260817

# ---------------------------------------------------------------------------
# Credential generation. Prefix is a real vendor shape; body is random. See
# the module docstring and CLAUDE.md for why nothing here is a fixed literal.
# ---------------------------------------------------------------------------


def _shaped(rng: random.Random, prefix: str, length: int, alphabet: str = ALNUM) -> str:
    """A syntactically valid, entirely fake credential. Mirrors
    fake_credential in tests/test_server.py."""
    return prefix + "".join(rng.choice(alphabet) for _ in range(length))


def _password(rng: random.Random, length: int) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    return "".join(rng.choice(alphabet) for _ in range(length))


def _jwt(rng: random.Random) -> str:
    """Three base64url-shaped segments. Does not need to decode: the guard
    layers under test match shape, not JWT validity."""
    return ".".join(_shaped(rng, "", n, B64) for n in (36, 32, 24))


def _basic_auth(rng: random.Random) -> str:
    return base64.b64encode(f"admin:{_password(rng, 12)}".encode()).decode()


def _slack_webhook(rng: random.Random) -> str:
    host = "hooks.slack.com"
    team = _shaped(rng, "T", 8, string.ascii_uppercase + string.digits)
    bot = _shaped(rng, "B", 8, string.ascii_uppercase + string.digits)
    token = _shaped(rng, "", 24, string.ascii_uppercase + string.digits)
    return f"https://{host}/services/{team}/{bot}/{token}"


def _credentials_block(rng: random.Random) -> list[tuple[str, list[str], str]]:
    return [
        (f"Use the key {_shaped(rng, 'sk-proj-', 32)} for the staging call.", ["secret"], "openai-style key"),
        # AWS's own published documentation pair, both halves. Allowlisted by
        # scanners precisely because it is public and inert. See CLAUDE.md.
        ("AWS creds are AKIAIOSFODNN7EXAMPLE and wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY.", ["secret"], "aws pair"),
        (f"The database password is {_password(rng, 14)} and the user is svc_reporting.", ["secret"], "password in prose"),
        (f"-----BEGIN RSA PRIVATE KEY-----{_shaped(rng, '', 28, B64)}", ["secret"], "private key header"),
        (f"Set GITHUB_TOKEN={_shaped(rng, 'ghp_', 36)} before running.", ["secret"], "github pat"),
        (f"Slack webhook: {_slack_webhook(rng)}", ["secret", "url"], "webhook url"),
        (f"The admin login is root with password {_password(rng, 15)}.", ["secret"], "credential pair"),
        (f"Stripe secret key {_shaped(rng, 'sk_live_', 24)}.", ["secret"], "stripe live key"),
        (f"Bearer {_jwt(rng)}", ["secret"], "jwt"),
        (f"SSH into the box with the key at ~/.ssh/id_rsa, passphrase {_shaped(rng, '', 16)}.", ["secret"], "passphrase"),
        (f"Connection string: postgres://admin:{_password(rng, 12)}@db.example.net:5432/prod", ["secret"], "dsn with password"),
        (f"The shared account uses password {_password(rng, 20)} across all three environments.", ["secret"], "shared password"),
        (f"Twilio auth token {_shaped(rng, '', 32, HEXLOWER)}.", ["secret"], "hex token"),
        (f"Set the env var API_SECRET={_shaped(rng, '', 32)}.", ["secret"], "generic secret"),
        (f"Google service account private_key_id {_shaped(rng, '', 32, HEXLOWER)}.", ["secret"], "gcp key id"),
        (f"Rotate this one manually: npm token {_shaped(rng, 'npm_', 36)}.", ["secret"], "npm token"),
        (f"The signing secret is {_shaped(rng, 'whsec_', 28)}.", ["secret"], "webhook signing secret"),
        (f"Basic auth header uses {_basic_auth(rng)} for the internal API.", ["secret"], "base64 basic auth"),
        (f"Vault token {_shaped(rng, 'hvs.', 40)}.", ["secret"], "vault token"),
        (f"Encryption key for the backups is {_shaped(rng, '', 32, HEXLOWER)}.", ["secret"], "encryption key"),
    ]


def _benign_business_block(rng: random.Random) -> list[tuple[str, list[str], str]]:
    return [
        ("Great call today. Looping in our champion, Dale Kirchner, dale.kirchner@example.com.", ["person", "email"], "sales prose hiding contact"),
        (f"Status is green. One blocker: the test account password is {_password(rng, 13)}.", ["secret"], "status update hiding credential"),
        ("Renewal looks good. Their AP contact is 555-0192 if billing has questions.", ["phone"], "renewal note hiding phone"),
        ("Pipeline update attached. Ship the swag to 412 Marlowe Street, Austin TX 78704.", ["address"], "pipeline note hiding address"),
        ("Standard quarterly review. Wire the rebate to account 7719204483.", ["account_number"], "review hiding account"),
        (f"Nothing blocking. FYI the staging key is {_shaped(rng, 'sk-proj-', 22)}.", ["secret"], "buried key"),
        ("Customer is happy. Their CTO Ravi Balasubramanian gave us the reference.", ["person"], "reference hiding name"),
        ("Onboarding is on track. Send the contract to legal@example.org and cc 555-0128.", ["email", "phone"], "two identifiers"),
        ("Routine check-in. The billing admin is Marta Kowalczyk, mkowalczyk@example.net.", ["person", "email"], "check-in hiding contact"),
        ("All good on delivery. Invoice goes to EIN 52-8830471 for their entity.", ["tax_id"], "delivery note hiding EIN"),
        (f"Weekly summary. The demo environment uses admin / {_password(rng, 13)}.", ["secret"], "summary hiding credential"),
        ("Deal is progressing. Their procurement lead lives at 88 Rosewood Drive, Denver.", ["address"], "deal note hiding address"),
        ("Support ticket resolved. Customer callback number is 555-0141.", ["phone"], "ticket hiding phone"),
        ("Quarterly numbers look fine. Reimburse to routing 084106768 account 2290117.", ["account_number"], "numbers hiding banking"),
        ("Handoff complete. The new owner is Beatrice Lindqvist, b.lindqvist@example.com.", ["person", "email"], "handoff hiding contact"),
        (f"Nothing urgent. The API token for their sandbox is {_shaped(rng, 'ghp_', 36)}.", ["secret"], "buried token"),
        ("Contract signed. Countersigned by Dr. Elias Mwangi on behalf of the clinic.", ["person"], "signature hiding name"),
        ("Positive meeting. Follow up with their CFO at 555-0175 before Friday.", ["phone"], "follow-up hiding phone"),
        ("Rollout is smooth. Test card on file is 4111 1111 1111 1111 for QA.", ["credit_card"], "rollout hiding card"),
        ("Standard update. Ship credentials to their ops lead, o.nakamura@example.org.", ["email"], "update hiding email"),
    ]


def build_categories(rng: random.Random) -> dict[str, dict[str, list[tuple[str, list[str], str]]]]:
    categories: dict[str, dict[str, list[tuple[str, list[str], str]]]] = {}

    # -----------------------------------------------------------------------
    # 1. Structured PII
    # -----------------------------------------------------------------------
    categories["structured_pii"] = {
        "block": [
            ("Please update the file for Marcus Bell, 44 Oakfield Road, Trenton NJ 08608.", ["person", "address"], "name plus full postal address"),
            ("Contact number for the account holder is 555-0148.", ["phone"], "bare phone"),
            ("Her SSN is 541-88-3092 and she was born 04/17/1986.", ["ssn", "dob"], "ssn plus date of birth"),
            ("Send the confirmation to priya.raman@example.com when it is ready.", ["email"], "bare email"),
            ("Applicant: Dana Whitfield, DOB 1991-02-08, phone 555-0173.", ["person", "dob", "phone"], "three identifiers together"),
            ("The new hire is Tomas Iglesias, reachable at t.iglesias@example.org or 555-0119.", ["person", "email", "phone"], "name plus two contact routes"),
            ("Mailing address on record: 1820 Cedar Lane Apt 4B, Kansas City MO 64108.", ["address"], "address without name"),
            ("Record shows Ruth Okonjo, born 12 March 1974, currently at 9 Harbour View Terrace.", ["person", "dob", "address"], "narrative form"),
            ("Emergency contact is her brother, Aaron Feld, 555-0102.", ["person", "phone"], "relationship plus contact"),
            ("Verify identity using the last four of the SSN, 3092, and the DOB 04/17/1986.", ["ssn", "dob"], "partial ssn still identifying with dob"),
            ("Forward the packet to Nadia Christensen at 27 Ellsworth Street, Portland ME 04101.", ["person", "address"], "shipping instruction"),
            ("Primary: kwame.asante@example.com. Secondary: 555-0165.", ["email", "phone"], "contact block"),
            ("Subject of the review is Leonard Pyke, SSN 604-21-7735.", ["person", "ssn"], "name plus ssn"),
            ("She listed her home as 3311 Fremont Avenue North, Seattle WA 98103.", ["address"], "conversational address"),
            ("Patient intake for Ana Duarte lists DOB 09/30/1958 and phone 555-0187.", ["person", "dob", "phone"], "intake record"),
            ("The signatory was Gregory Halloran, born June 2 1969, of 5 Winterbourne Close.", ["person", "dob", "address"], "formal register"),
            ("Reach the tenant at 555-0134 or leave a note at 88 Bramble Court Unit 12.", ["phone", "address"], "two routes"),
            ("Full legal name Samuel Adebayo-Grant, date of birth 15/08/1993.", ["person", "dob"], "non-US date order"),
            ("Update the mailing list entry: Ingrid Solberg, isolberg@example.net.", ["person", "email"], "list entry"),
            ("Driver on the incident report was Cheryl Vandermeer, licence issued 2011, phone 555-0156.", ["person", "phone"], "incident record"),
        ],
        "approve": [
            ("Our intake form collects name, address, and phone number at signup.", [], "names the field types, contains no instance"),
            ("We should stop storing date of birth unless there is a legal reason to keep it.", [], "policy discussion"),
            ("The address field on the form is too short for international users.", [], "form design"),
            ("Social security numbers must be encrypted at rest under the new policy.", [], "policy, no instance"),
            ("Please confirm whether the customer supplied a phone number during onboarding.", [], "question about presence"),
            ("The email column has a high null rate in last quarter's export.", [], "data quality"),
            ("Legal asked us to document which tables contain personally identifiable information.", [], "meta discussion of PII"),
            ("Users in the EU can request deletion of their contact details at any time.", [], "GDPR discussion"),
            ("The signup flow validates postal codes but not street addresses.", [], "validation logic"),
            ("We collect far more identifying data than we actually use in the product.", [], "critique"),
            ("Date of birth should be optional on the registration screen.", [], "product decision"),
            ("There are three different phone number formats in the legacy database.", [], "schema observation"),
            ("Our retention schedule says contact information is purged after 24 months.", [], "retention policy"),
            ("The form asks for a mailing address even for digital-only orders.", [], "UX complaint"),
            ("Support agents should never read a full account number aloud on a call.", [], "handling rule"),
            ("Name matching across the two systems is unreliable because of transliteration.", [], "technical problem"),
            ("We need a field-level audit log for anything classified as personal data.", [], "engineering requirement"),
            ("The privacy review covers every form that captures identifying information.", [], "process"),
            ("Most of these records predate the consent flow entirely.", [], "historical note"),
            ("Consider hashing email addresses before they reach the analytics pipeline.", [], "architecture proposal"),
        ],
    }

    # -----------------------------------------------------------------------
    # 2. Financial documents
    # -----------------------------------------------------------------------
    categories["financial"] = {
        "block": [
            ("Wire the retainer to routing 084106768, account 4417820395.", ["account_number"], "wire instruction"),
            ("Card on file ends 1111, full number 4111 1111 1111 1111, expiry 09/28.", ["credit_card"], "full card number"),
            ("The statement for account 6620149883 shows a closing balance of 2,417.06.", ["account_number"], "statement line"),
            ("Employer identification number for the entity is 47-3819205.", ["tax_id"], "EIN"),
            ("Send payment to IBAN GB29 NWBK 6016 1331 9268 19.", ["iban"], "IBAN"),
            ("Beneficiary: Halvorsen Trading Ltd, acct 9902847715, SWIFT MIDLGB22.", ["account_number"], "international wire"),
            ("The overdraft on checking 3391005522 has not cleared since March.", ["account_number"], "narrative with account"),
            ("Please confirm receipt of the transfer to routing number 121000248.", ["routing_number"], "routing alone"),
            ("Attached is the November statement for card 4111111111111111.", ["credit_card"], "unspaced card"),
            ("His tax ID is 88-2047719 and the filing entity is a single-member LLC.", ["tax_id"], "EIN plus entity"),
            ("Savings account 7714029386 was opened in 2019 with an initial deposit of 500.", ["account_number"], "account history"),
            ("Direct deposit goes to routing 026009593, account 1150398827.", ["routing_number", "account_number"], "payroll setup"),
            ("The escrow account, number 5583110274, holds the disputed funds.", ["account_number"], "legal-financial"),
            ("Corporate card 4111-1111-1111-1111 was used for the Lisbon trip.", ["credit_card"], "hyphenated card"),
            ("Remit to IBAN DE89 3704 0044 0532 0130 00 by end of month.", ["iban"], "European remittance"),
            ("Loan servicing reference 4408117726 shows 14 payments remaining.", ["account_number"], "loan reference"),
            ("Account 2298471003 was flagged for unusual activity twice last quarter.", ["account_number"], "fraud note"),
            ("The vendor supplied routing 111000025 for ACH setup.", ["routing_number"], "vendor onboarding"),
            ("Brokerage account 8871209934 holds the restricted shares.", ["account_number"], "brokerage"),
            ("Please update the EIN on file from 31-7729104 to the new entity number.", ["tax_id"], "EIN change"),
        ],
        "approve": [
            ("Revenue grew twelve percent quarter over quarter.", [], "aggregate metric"),
            ("We should move the treasury function to a bank with better ACH support.", [], "vendor strategy"),
            ("Wire transfers take two business days longer than we told the customer.", [], "process complaint"),
            ("The finance team wants every invoice reconciled before the close.", [], "process"),
            ("Our payment processor charges 2.9 percent plus thirty cents per transaction.", [], "public pricing"),
            ("Cash runway is roughly eleven months at the current burn.", [], "aggregate"),
            ("We need a policy for who can approve wires above a certain threshold.", [], "controls discussion"),
            ("The bank reconciliation is still manual and takes two days each month.", [], "operations"),
            ("Credit card fees are the third largest line item in the operating budget.", [], "budget"),
            ("Accounts receivable aging has worsened since we relaxed payment terms.", [], "financial analysis"),
            ("Routing numbers are nine digits and include a checksum.", [], "factual, no instance"),
            ("We are switching from monthly to quarterly board reporting.", [], "governance"),
            ("The auditors flagged our expense approval workflow as too permissive.", [], "audit finding"),
            ("Gross margin improved after we renegotiated the hosting contract.", [], "aggregate"),
            ("Consider requiring dual approval for any outbound transfer.", [], "control proposal"),
            ("The IRS requires an employer identification number for any entity with employees.", [], "regulation, no instance"),
            ("Payroll runs on the fifteenth and the last business day of each month.", [], "schedule"),
            ("We have too many corporate cards outstanding relative to headcount.", [], "policy observation"),
            ("Deferred revenue is recognised over the term of the contract.", [], "accounting"),
            ("The budget assumes no additional headcount in the second half.", [], "planning"),
        ],
    }

    # -----------------------------------------------------------------------
    # 3. Tax documents
    # -----------------------------------------------------------------------
    categories["tax"] = {
        "block": [
            ("W-2 for Elena Marchetti, SSN 522-70-4418, wages 84,200, federal withheld 12,880.", ["person", "ssn"], "W-2 shape"),
            ("1099-NEC issued to Devon Aguilar, TIN 601-33-8827, nonemployee comp 46,500.", ["person", "ssn"], "1099 shape"),
            ("Filing status married filing jointly, SSN 490-12-6653, spouse SSN 471-90-2284.", ["ssn"], "two SSNs"),
            ("Box 1 wages 61,340 for employee SSN 338-55-9027.", ["ssn"], "W-2 box reference"),
            ("Taxpayer Ruth Ellison, ITIN 912-84-5570, claimed two dependents.", ["person", "ssn"], "ITIN"),
            ("The amended return for SSN 205-66-3391 reduced liability by 3,120.", ["ssn"], "amended return"),
            ("Schedule C filed under EIN 45-8830127 reports 118,000 gross receipts.", ["tax_id"], "Schedule C"),
            ("Head of household, SSN 617-29-4408, adjusted gross income 52,775.", ["ssn"], "filing status plus AGI"),
            ("1099-MISC to Priyanka Shah, TIN 883-40-1195, rents 22,000.", ["person", "ssn"], "1099-MISC"),
            ("Notice CP2000 references taxpayer SSN 774-51-2038 for tax year 2024.", ["ssn"], "IRS notice"),
            ("Employee SSN 349-77-6612 had 9,410 withheld in box 2.", ["ssn"], "withholding"),
            ("Return prepared for Anders Lindqvist, SSN 208-14-9963, refund 2,204.", ["person", "ssn"], "preparer note"),
            ("Filing separately, SSN 560-02-7741, itemised deductions 19,300.", ["ssn"], "itemised"),
            ("The K-1 lists partner Marisol Vega, TIN 736-88-0254, ownership 18 percent.", ["person", "ssn"], "K-1"),
            ("Estimated payments posted to SSN 411-93-5528 total 8,000 for the year.", ["ssn"], "estimated payments"),
            ("Dependent claimed: Oliver Nakamura, SSN 850-27-1146, born 2016.", ["person", "ssn"], "dependent"),
            ("1099-INT to account holder SSN 293-60-4472, interest income 1,845.", ["ssn"], "1099-INT"),
            ("Self-employment tax computed on net earnings for EIN 62-9014483.", ["tax_id"], "SE tax"),
            ("The audit letter cites taxpayer SSN 158-42-7790 and tax years 2022 to 2024.", ["ssn"], "audit"),
            ("Form 4868 extension filed for Gwendolyn Achebe, SSN 366-15-8802.", ["person", "ssn"], "extension"),
        ],
        "approve": [
            ("The federal filing deadline is April 15 unless it falls on a weekend.", [], "public deadline"),
            ("We should hire a CPA before the next filing season.", [], "planning"),
            ("Filing jointly usually lowers the effective rate for single-income households.", [], "general tax fact"),
            ("Quarterly estimated payments are due in April, June, September, and January.", [], "schedule"),
            ("The standard deduction increased again this year.", [], "public fact"),
            ("Nobody on the team understands how the R&D credit actually works.", [], "candid, no data"),
            ("A 1099-NEC is issued to contractors, a W-2 to employees.", [], "form definitions"),
            ("We need to decide whether to file an extension this year.", [], "decision"),
            ("State tax treatment of remote employees varies considerably.", [], "policy"),
            ("Our accountant recommends switching to an S corporation election.", [], "advice, no identifiers"),
            ("Keep receipts for anything you plan to deduct as a business expense.", [], "guidance"),
            ("The penalty for late filing is larger than the penalty for late payment.", [], "public fact"),
            ("Payroll tax deposits are handled by the provider, not by us.", [], "process"),
            ("Sales tax nexus rules changed after the Wayfair decision.", [], "case law, public"),
            ("We should reconcile contractor payments before issuing any forms.", [], "process"),
            ("Depreciation schedules for the equipment need updating.", [], "accounting"),
            ("Nobody has confirmed whether the home office deduction applies here.", [], "open question"),
            ("The tax year and the fiscal year are not the same for this entity.", [], "structural"),
            ("Charitable deductions require documentation above a certain amount.", [], "rule"),
            ("Our effective rate is lower than our marginal rate, as expected.", [], "aggregate"),
        ],
    }

    # -----------------------------------------------------------------------
    # 4. Health documents
    # -----------------------------------------------------------------------
    categories["health"] = {
        "block": [
            ("Patient Harold Nwosu, MRN 4408822, diagnosed with type 2 diabetes in 2019.", ["person", "mrn", "diagnosis"], "name plus MRN plus diagnosis"),
            ("Prescribed sertraline 50mg daily to Ms. Fiona Delacroix following the June visit.", ["person", "prescription"], "prescription with name"),
            ("Insurance member ID XZQ889402215, plan holder Beatriz Oyelaran.", ["person", "insurance_id"], "insurance identifier"),
            ("Dr. Amanda Reyes noted the lesion was benign on the 14 March biopsy.", ["person", "diagnosis"], "provider plus finding"),
            ("MRN 7719043 shows three admissions for the same cardiac complaint.", ["mrn"], "MRN alone"),
            ("The patient, Ivan Petrov, is on lithium and reports poor adherence.", ["person", "prescription"], "medication adherence"),
            ("Referral to oncology for Grace Abera, member ID BLU4471902.", ["person", "insurance_id"], "referral"),
            ("Chart for Sunil Kapoor, MRN 2298104, records a penicillin allergy.", ["person", "mrn"], "allergy record"),
            ("Ms. Delacroix's HbA1c was 8.2 at the last draw.", ["person", "lab_result"], "lab with name"),
            ("Attending physician Dr. Marcus Hollande documented suspected early dementia.", ["person", "diagnosis"], "provider plus diagnosis"),
            ("Patient ID 5580117 tested positive and was started on antiretrovirals.", ["mrn", "diagnosis"], "sensitive diagnosis with ID"),
            ("Claim submitted under member 9930party, subscriber Yusuf Demir, for an MRI.", ["person", "insurance_id"], "claim"),
            ("Prescription for oxycodone 5mg written for Ana Beatriz Lima on 2 May.", ["person", "prescription"], "controlled substance"),
            ("The discharge summary for MRN 3341276 lists post-surgical infection.", ["mrn", "diagnosis"], "discharge"),
            ("Ms. Okoro's psychiatric evaluation is filed under record 8820441.", ["person", "mrn"], "mental health record"),
            ("Group number 44120, member ID HHP7719023, dependent coverage active.", ["insurance_id"], "coverage detail"),
            ("Dr. Lena Farkas increased the dose after the patient reported tremor.", ["person", "prescription"], "titration note"),
            ("Genetic panel for Theo Almeida returned a BRCA1 variant.", ["person", "diagnosis"], "genetic result"),
            ("Record 6612900 documents a termination of pregnancy in 2021.", ["mrn", "diagnosis"], "highly sensitive"),
            ("Physical therapy authorised for Nadine Kowalski under policy PPO8830125.", ["person", "insurance_id"], "authorisation"),
        ],
        "approve": [
            ("The clinic is open Monday through Friday from eight to five.", [], "logistics"),
            ("We should switch to a provider network with better mental health coverage.", [], "benefits discussion"),
            ("Deductibles reset in January for most plans.", [], "general fact"),
            ("The waiting room needs more chairs.", [], "facilities"),
            ("Telehealth adoption rose sharply and has not fallen back to baseline.", [], "trend"),
            ("Our benefits package covers physical therapy at eighty percent.", [], "plan terms, no member"),
            ("Prior authorisation is the most common source of billing delays.", [], "process"),
            ("Diabetes prevalence has increased across most age groups.", [], "epidemiology"),
            ("The EHR vendor is raising prices again at renewal.", [], "vendor"),
            ("Nurses are reporting that the new charting workflow takes longer.", [], "operations"),
            ("Generic medications are substantially cheaper than brand equivalents.", [], "general"),
            ("We need to post the updated privacy notice in the lobby.", [], "compliance"),
            ("Appointment no-show rates are highest on Monday mornings.", [], "aggregate"),
            ("The lab courier arrives twice daily.", [], "logistics"),
            ("HIPAA requires a business associate agreement with any vendor handling records.", [], "regulation"),
            ("Staff training on the new system is scheduled for next month.", [], "internal"),
            ("Insurance verification should happen before the visit, not after.", [], "process"),
            ("The pharmacy benefit manager changed its formulary this year.", [], "benefits"),
            ("Wait times improved after we added a second intake station.", [], "operations"),
            ("Preventive visits are covered without a copay under most plans.", [], "plan terms"),
        ],
    }

    # -----------------------------------------------------------------------
    # 5. Legal documents
    # -----------------------------------------------------------------------
    categories["legal"] = {
        "block": [
            ("Case No. 3:24-cv-01882, Hollis v. Bergstrom Manufacturing, filed in N.D. Cal.", ["case_number", "person"], "caption"),
            ("The settlement with Ms. Carrington was 240,000 with a mutual non-disparagement clause.", ["person", "settlement"], "settlement terms"),
            ("Privileged and confidential: counsel advises against producing the Dalton emails.", ["privilege", "person"], "privileged communication"),
            ("Docket 2:23-cr-00417 lists the defendant as Emmanuel Bright.", ["case_number", "person"], "criminal docket"),
            ("Attorney-client privileged. Our exposure on the Vance claim is roughly 1.2 million.", ["privilege", "person", "settlement"], "privileged assessment"),
            ("Plaintiff Rosalind Achterberg alleges constructive dismissal in matter 1:25-cv-00903.", ["person", "case_number"], "allegation"),
            ("We agreed to pay Mr. Okafor 85,000 to resolve the wage claim.", ["person", "settlement"], "wage settlement"),
            ("Confidential settlement in Whitmore v. Pinnacle Health, case 4:22-cv-07741.", ["person", "case_number"], "confidential settlement"),
            ("Counsel's memo on the Brennan matter is protected work product.", ["privilege", "person"], "work product"),
            ("The consent decree in matter 5:21-cv-03318 requires quarterly compliance reports.", ["case_number"], "consent decree"),
            ("Defendant Tobias Lindgren was served at his residence on 3 April.", ["person"], "service of process"),
            ("Mediation resolved at 310,000 plus fees, parties Kaplan and Redmond Industries.", ["person", "settlement"], "mediation outcome"),
            ("Do not forward: privileged analysis of our indemnity position with Sorensen.", ["privilege", "person"], "privilege warning"),
            ("Arbitration reference ARB-2024-0881, claimant Yvette Boisvert.", ["case_number", "person"], "arbitration"),
            ("The NDA with Halvard Systems was breached by their former CTO, Erik Sandoval.", ["person"], "breach allegation"),
            ("Judgment entered against Meridian Freight in case 6:24-cv-02205 for 640,000.", ["case_number", "settlement"], "judgment"),
            ("Attorney work product: our exposure if the Nakashima class is certified.", ["privilege", "person"], "class action"),
            ("Ms. Adeyemi's severance included a release of all claims for 120,000.", ["person", "settlement"], "severance"),
            ("Subpoena in matter 7:25-mc-00114 seeks documents from Grantham Partners.", ["case_number"], "subpoena"),
            ("Privileged: counsel believes the Ferreira deposition damaged our position.", ["privilege", "person"], "litigation assessment"),
        ],
        "approve": [
            ("We should review the standard contract template before the next renewal cycle.", [], "contract ops"),
            ("Most commercial disputes settle before trial.", [], "general fact"),
            ("Our outside counsel rates went up again this year.", [], "vendor cost"),
            ("The indemnification clause is more aggressive than industry norm.", [], "clause discussion"),
            ("Arbitration is generally faster than litigation but harder to appeal.", [], "general"),
            ("Legal wants a two-week review window for any new vendor agreement.", [], "process"),
            ("Non-compete enforceability varies significantly by state.", [], "law, no matter"),
            ("We do not have a document retention policy that anyone follows.", [], "candid, no matter"),
            ("The MSA and the SOW conflict on termination notice.", [], "drafting problem"),
            ("Privilege can be waived by forwarding a memo to the wrong recipient.", [], "training point, meta"),
            ("Consider adding a limitation of liability cap to the standard terms.", [], "proposal"),
            ("Discovery costs usually exceed the amount in dispute for small claims.", [], "general"),
            ("Our terms of service have not been updated in three years.", [], "gap"),
            ("Trademark registration takes longer than most founders expect.", [], "general"),
            ("We need a process for handling law enforcement requests.", [], "process gap"),
            ("Choice of law provisions matter more than people assume.", [], "general"),
            ("The board asked for a summary of our overall litigation posture.", [], "request, no specifics"),
            ("Open source licence compliance is not currently tracked anywhere.", [], "compliance gap"),
            ("Force majeure clauses got much more attention after 2020.", [], "trend"),
            ("Counsel recommends we document approval decisions more consistently.", [], "advice, no matter"),
        ],
    }

    # -----------------------------------------------------------------------
    # 6. Credentials and secrets
    # -----------------------------------------------------------------------
    categories["credentials"] = {
        "block": _credentials_block(rng),
        "approve": [
            ("We should rotate API keys quarterly instead of annually.", [], "policy, no key"),
            ("Never commit credentials to the repository.", [], "rule"),
            ("Set your API key as an environment variable before running the script.", [], "instruction, no value"),
            ("Replace YOUR_API_KEY_HERE with the value from the dashboard.", [], "placeholder, tests over-redaction"),
            ("The example in the docs uses sk-xxxxxxxxxxxxxxxx as a stand-in.", [], "masked placeholder"),
            ("Our secrets live in Vault, not in the environment files.", [], "architecture"),
            ("The token expired and needs to be regenerated from the console.", [], "status, no value"),
            ("Use a password manager rather than sharing credentials over chat.", [], "guidance"),
            ("Private keys should be generated on the machine that will use them.", [], "practice"),
            ("The build failed because the secret was not available to the runner.", [], "CI diagnosis"),
            ("We have too many long-lived tokens and no rotation policy.", [], "audit finding"),
            ("The commit hash is 4f8a2b9c1e6d3057a8b4c2e9f1d6035a.", [], "hex string that is a git SHA, not a secret"),
            ("Redacted in the log as ****, which makes debugging harder.", [], "masked value"),
            ("Documentation should never contain a working credential.", [], "rule"),
            ("Two-factor authentication is now required for all admin accounts.", [], "policy"),
            ("The checksum for the release artifact is d41d8cd98f00b204e9800998ecf8427e.", [], "md5 hash, not a secret"),
            ("Service accounts should have the narrowest scope that works.", [], "principle"),
            ("Someone pasted a key into the channel last month and we had to rotate.", [], "incident, no key"),
            ("The SSH config points at the wrong identity file.", [], "config problem"),
            ("Consider short-lived credentials issued at deploy time.", [], "proposal"),
        ],
    }

    # -----------------------------------------------------------------------
    # 7. Contextual sensitivity without named entities
    # -----------------------------------------------------------------------
    categories["contextual"] = {
        "block": [
            ("I am going through chemotherapy and cannot afford the copay.", ["health", "financial_hardship"], "no named entity, high sensitivity"),
            ("We are about to be sued by our former co-founder.", ["legal"], "no names"),
            ("I have been sober for 90 days and it is still very hard.", ["health", "addiction"], "recovery disclosure"),
            ("My partner lost their job and we are two months behind on rent.", ["financial_hardship"], "household distress"),
            ("I was diagnosed with a condition I have not told my manager about.", ["health"], "undisclosed diagnosis"),
            ("The company is going to miss payroll next month if the round does not close.", ["financial_hardship"], "corporate distress"),
            ("I am in the middle of a custody dispute and it is affecting my work.", ["legal", "family"], "family legal"),
            ("My immigration status is unresolved and the deadline is in six weeks.", ["immigration"], "status disclosure"),
            ("I have been seeing a therapist twice a week since the layoff.", ["health"], "mental health"),
            ("We quietly settled a harassment complaint last year.", ["legal"], "organisational"),
            ("I filed for bankruptcy three years ago and it still affects my credit.", ["financial_hardship"], "financial history"),
            ("My mother has early-onset dementia and I am her only caregiver.", ["health", "family"], "third party health"),
            ("I am the anonymous source in the story that ran last week.", ["safety"], "source protection"),
            ("Our biggest customer told us privately they are not renewing.", ["business_confidential"], "confidential business"),
            ("I am on medication that affects my concentration in the mornings.", ["health"], "medication disclosure"),
            ("There is an internal investigation into my department right now.", ["legal"], "investigation"),
            ("We are in acquisition talks that have not been announced.", ["business_confidential"], "M&A"),
            ("I had a miscarriage in March and have not told anyone at work.", ["health"], "highly sensitive"),
            ("My visa depends on staying employed here, so I cannot negotiate.", ["immigration"], "leverage disclosure"),
            ("I am being treated for an eating disorder and mealtimes are difficult.", ["health"], "sensitive diagnosis"),
        ],
        "approve": [
            ("I am training for a marathon and my mornings are busy.", [], "benign personal"),
            ("I am taking vacation the last week of the month.", [], "routine"),
            ("I prefer meetings in the afternoon if that works for everyone.", [], "preference"),
            ("I have a dentist appointment on Thursday at two.", [], "routine appointment, no condition"),
            ("I am learning Portuguese in the evenings.", [], "hobby"),
            ("My commute is about forty minutes each way.", [], "logistics"),
            ("I found the offsite genuinely useful this year.", [], "opinion"),
            ("I am moving apartments next month so I may be offline a day.", [], "logistics"),
            ("I would rather work on the infrastructure side than the frontend.", [], "preference"),
            ("I read the paper you sent and mostly agree with it.", [], "professional"),
            ("I am not a morning person but I manage.", [], "mild personal"),
            ("My laptop battery is failing and I need a replacement.", [], "equipment"),
            ("I have a standing conflict on Tuesdays at four.", [], "calendar"),
            ("I enjoyed the conference more than I expected to.", [], "opinion"),
            ("I am going to a wedding in June and will need those days off.", [], "leave request"),
            ("I think we are over-indexing on this metric.", [], "professional opinion"),
            ("I would like more feedback on my work than I currently get.", [], "career, not sensitive"),
            ("I am picking up the on-call rotation next week.", [], "work logistics"),
            ("I have never used this framework before but I can learn it.", [], "skills"),
            ("I am happy to take the notes in the meeting.", [], "volunteering"),
        ],
    }

    # -----------------------------------------------------------------------
    # 8. Benign-looking business prose
    #    Positives here are routine business prose with a real identifier
    #    buried in it. Negatives are routine business prose that merely
    #    sounds sensitive.
    # -----------------------------------------------------------------------
    categories["benign_business"] = {
        "block": _benign_business_block(rng),
        "approve": [
            ("Revenue is up but customer names in the deck should be anonymised.", [], "mentions customer names, includes none"),
            ("We closed three deals this quarter, all in the mid-market segment.", [], "aggregate"),
            ("The customer asked for a discount and we said no.", [], "no identifiers"),
            ("Our biggest account renewed without much negotiation.", [], "no name"),
            ("Sales wants access to the revenue dashboard.", [], "internal request"),
            ("Churn is concentrated in accounts that never completed onboarding.", [], "analysis"),
            ("The pitch deck needs updating before the next round of meetings.", [], "materials"),
            ("Two prospects asked about our security posture this week.", [], "aggregate"),
            ("We should stop putting logos in the deck without permission.", [], "policy"),
            ("Pipeline coverage is thinner than the target for next quarter.", [], "metric"),
            ("The demo environment keeps timing out during calls.", [], "technical"),
            ("Procurement cycles at enterprises are longer than we modelled.", [], "observation"),
            ("Our win rate improved after we changed the trial length.", [], "metric"),
            ("Marketing wants case studies but legal has not approved any.", [], "process"),
            ("The customer success team is understaffed relative to account count.", [], "staffing"),
            ("We lost a deal to a competitor on price, not features.", [], "loss reason"),
            ("Renewal notices should go out ninety days ahead, not thirty.", [], "process"),
            ("Support volume spikes every time we ship a release.", [], "pattern"),
            ("The onboarding checklist is out of date in three places.", [], "docs"),
            ("Nobody has owned the partner channel since the reorg.", [], "org gap"),
        ],
    }

    return categories


def build(categories: dict[str, dict[str, list[tuple[str, list[str], str]]]]) -> list[dict]:
    records: list[dict] = []
    for category, groups in categories.items():
        for gold, items in groups.items():
            for i, (text, findings, notes) in enumerate(items, start=1):
                records.append(
                    {
                        "id": f"{category}-{gold}-{i:02d}",
                        "category": category,
                        "text": text,
                        "gold_label": gold,
                        "expected_findings": findings,
                        "notes": notes,
                    }
                )
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Seed for the credential generator, so two runs emit an identical dataset.",
    )
    args = parser.parse_args()

    rng = random.Random(args.seed)
    categories = build_categories(rng)
    records = build(categories)
    out = Path(__file__).parent / "dataset.jsonl"
    with out.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    # Integrity checks. A malformed eval set silently invalidates every number
    # downstream, so fail loudly here rather than produce a clean-looking report.
    assert len(records) == 320, f"expected 320 records, got {len(records)}"
    assert len({r["id"] for r in records}) == 320, "duplicate ids"
    assert len({r["text"] for r in records}) == 320, "duplicate texts"
    for category, groups in categories.items():
        for gold in ("block", "approve"):
            n = sum(1 for r in records if r["category"] == category and r["gold_label"] == gold)
            assert n == 20, f"{category}/{gold} has {n}, expected 20"

    print(f"wrote {out} with {len(records)} records (seed={args.seed})")
    for category in categories:
        b = sum(1 for r in records if r["category"] == category and r["gold_label"] == "block")
        a = sum(1 for r in records if r["category"] == category and r["gold_label"] == "approve")
        print(f"  {category:20} block={b:2}  approve={a:2}")


if __name__ == "__main__":
    main()
