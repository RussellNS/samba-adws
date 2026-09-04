Do not use em dashes anywhere.  When quoting use the appropriate, normal single or double quote, not smart quotes.  Limit the use of semi-colons when just starting a new sentence will do.

For scripts formatting, use a 79 character width limit on docstring and block comments.  Ignore this for inline comments.  Separate functions with 3 blank lines.

Any script versioning should be in an 'x.x.x' notation where:
- The first number notates a major functionality overhaul or a complete rewrite
- The second number notates new user functionality and/or capability
- The third number notates minor feature enhancements, minor updates, and/or bug fixes

Any 'change log' sections should be brief, 1 to 3 sentences, describing primarily what changed and maybe the reason for the change, not a rewrite of everything that changed.  The specifics of any change should be folded into the comments of the individual functions or inline comments as complete rewrites to accommodate the change as though the comment is an original reference to what's being commented on (i.e. no "this was," "this changed from," "this changed to," etc.).

Comment all functions with a header comment as well as a docstring.  Comment all code functional elements such that "future me" has a clear indicator of what the functional element is trying to accomplish, and if needed for clarity, include what the result will look like.

Here is an example of a introductory script docstring.  Match this style:
```
"""
------------------------------------------------------------------------------
Script Name:      ollama_analyze_discrepancy
Script Author:    Neal Russell
Author's Company: N/A
Script Created:   2026-Aug-09
Script Modified:  2026-Aug-14
Script Version:   1.0.3
Script Purpose:   Given the discrepancies found by 'validate_ollama_data',
                  re-fetch the receipt image and ask a (typically different,
                  configurable) Ollama model a focused, sectioned prompt
                  covering ONLY the flagged fields, then merge any
                  corrections back into the 'ollama' dict.

Script Desc:      This script will perform the following actions:
                    * Receive the 'ollama' dict from 'normalize_ollama_data',
                        the 'validation' dict from 'validate_ollama_data'
                        (wired as results.f.validation, containing
                        'result' and 'validation_detail'), and the
                        file/auth dicts from the preprocessor
                    * If result == "pass", exit immediately with no
                        Ollama call, no lock, no file fetch
                    * Otherwise, acquire the Ollama busy lock, re-fetch the
                        file from Nextcloud via WebDAV, convert to image(s)
                    * Build a prompt with one isolated section per distinct
                        discrepancy (amount reconciliation first, then one
                        section per flagged field), instructing the model
                        to answer each section independently
                    * Send image(s) + prompt to Ollama using the model
                        provided as a Windmill input (independent of the
                        model used in ollama_analyze_receipt)
                    * Parse the sectioned JSON reply and merge corrected
                        values into a copy of the original 'ollama' dict
                    * Recompute derived fields (over_50, tax_rate,
                        total_summary, time_12hr, time_24hr) against the
                        corrected values
                    * Return the corrected 'ollama' dict plus a
                        'corrected_fields' list for traceability

Script Reqs:      These 'Step Inputs' must be configured in Windmill:
                    * nextcloud_webdav
                        resource('u/windadmin/nextcloud_webdav')
                    * windmill_postgres
                        resource('u/windadmin/windmill_postgres')
                    * ollama_endpoint
                        http://ollama.vlab.host:11434
                    * ollama_model
                        (independent Windmill input from
                        ollama_analyze_receipt's model, so the two can be
                        tuned separately over time -- changes frequently
                        as models are evaluated against hallucination and
                        accuracy tradeoffs; not a fixed value)

Script Notes:     The arithmetic reconciliation section is framed as a
                  proofreading task against the ALREADY-EXTRACTED values
                  from the first pass, not a fresh open-ended extraction --
                  this avoids re-running the same extraction and risking a
                  second, different wrong answer. The model is explicitly
                  permitted to conclude nothing was misread.

                  Sections are isolated by prompt instruction only (one
                  inference pass, one context window) -- this is a soft
                  isolation guarantee, not the same as genuinely separate
                  calls. Kept to a single call because Ollama on this infra
                  serves one request at a time via the shared advisory
                  lock; multiple sequential calls per receipt would hurt
                  queue throughput under load.

                  This script does NOT clean numeric-string formatting or
                  fix category/description swaps -- that is
                  'normalize_ollama_data', called again downstream in the
                  flow after this script, same as after
                  'ollama_analyze_receipt'. The derived-field recompute
                  here (over_50, tax_rate, total_summary, time_12hr,
                  time_24hr) is done regardless, since those must reflect
                  whatever values THIS script returns, corrected or not.

                  EXPENSE_CATEGORIES below is a duplicate of the dict in
                  'ollama_analyze_receipt' and 'normalize_ollama_data'.
                  All three must be kept in sync manually until/unless a
                  shared resource is set up.

                  The 'ollama' dict's model_1st_pass field (set in
                  'ollama_analyze_receipt') is carried forward untouched
                  by this script via corrected_ollama = dict(ollama).
                  A separate 'model_2nd_pass' field is added ONLY when
                  this script actually runs a real second Ollama pass and
                  reaches the merge/recompute stage -- never on the early
                  "pass" exit (Step 0) and never on a JSON-parse-failure
                  early return (Step 5), since neither of those represents
                  a completed second pass with a usable result.

------------------------------------------------------------------------------
Execution Context: Windmill flow step -- not standalone executable.
                   Requires Windmill resource: nextcloud_webdav (object type)
                   Runtime dependencies: requests
------------------------------------------------------------------------------
Change Log:
  1.0.0 - Initial DEV version.
  1.0.1 - Added 'model_2nd_pass' to the returned ollama dict whenever
            this script actually runs and completes.
  1.0.2 - _build_arithmetic_section was modified to move minor functional
            parts to _build_discrepancy_prompt.
  1.0.3 - Added missing 'pymupdf>=1.0.0' Windmill dependency declaration.
------------------------------------------------------------------------------
To Do List:
  *  Consider a shared resource/module for EXPENSE_CATEGORIES so this
       copy and the ones in ollama_analyze_receipt and
       normalize_ollama_data can't drift out of sync.
------------------------------------------------------------------------------
"""
```

Any script provided by the user that does not meet the criteria above should be modified to include the criteria above, without the user having to say that.  However, once a script does meet the criteria, it should not be modified again, only new content changes should be added and or updated.