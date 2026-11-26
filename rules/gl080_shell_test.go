// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

func TestRefTest(t *testing.T) {
	for cond, want := range map[string]int{
		`[ "$CI_COMMIT_BRANCH" = "main" ]`:                 1,
		`[[ $CI_COMMIT_REF_NAME == $CI_DEFAULT_BRANCH ]]`:  0,
		`[ "$CI_DEFAULT_BRANCH" = "${CI_COMMIT_BRANCH}" ]`: 1,
		`test "$CI_COMMIT_REF_PROTECTED" = true`:           1,
		`[ "$CI_COMMIT_REF_PROTECTED" != "false" ]`:        1,
		`[ -n "$CI_COMMIT_TAG" ]`:                          1,
		`[ "$CI_COMMIT_TAG" != "" ]`:                       1,
		`! [ -z "$CI_COMMIT_TAG" ]`:                        1,
		`[ "$CI_COMMIT_BRANCH" != "main" ]`:                -1,
		`[ "$CI_COMMIT_REF_PROTECTED" = "false" ]`:         -1,
		`[ -z "$CI_COMMIT_TAG" ]`:                          -1,
		`[ "$CI_COMMIT_TAG" = "" ]`:                        -1,
		`! [ "$CI_COMMIT_BRANCH" = main ]`:                 -1,
		`[[ "$CI_COMMIT_BRANCH" == release* ]]`:            0,
		`[ "$CI_COMMIT_BRANCH" = "$TARGET" ]`:              0,
		`[ "$PUSH" = "yes" ]`:                              0,
		`[ "$CI_COMMIT_REF_PROTECTED" = maybe ]`:           0,
		`[ "$CI_COMMIT_TAG" = "v1" ]`:                      0,
		`[ -n "$CI_COMMIT_BRANCH" ]`:                       0,
		`[ -n $CI_COMMIT_TAG ]`:                            0,
		`[[ -n $CI_COMMIT_TAG ]]`:                          1,
		`[ $CI_COMMIT_BRANCH = main ]`:                     1,
		`[ $CI_COMMIT_BRANCH != main ]`:                    0,
		`[ "$CI_COMMIT_BRANCH" -eq 1 ]`:                    0,
		`[ "$CI_COMMIT_BRANCH" = main ] && [ "$X" ]`:       0,
		`grep -q x file`:                                   0,
	} {
		if got := refTest(cond); got != want {
			t.Errorf("refTest(%q) = %d, want %d", cond, got, want)
		}
	}
}

func TestExitGuardAt(t *testing.T) {
	for text, want := range map[string]bool{
		`if [ "$CI_COMMIT_BRANCH" != "$CI_DEFAULT_BRANCH" ]; then exit 0; fi`: true,
		`[ -n "$CI_COMMIT_TAG" ] || exit 0`:                                   true,
		`[ -z "$CI_COMMIT_TAG" ] && exit 0`:                                   true,
		`if [ "$CI_COMMIT_BRANCH" = main ]; then exit 0; fi`:                  false,
		`[ "$CI_COMMIT_BRANCH" = main ] && exit 0`:                            false,
		`[ -n "$SKIP" ] && exit 0`:                                            false,
		`exit 0`:                                                              false,
		`(if [ "$CI_COMMIT_BRANCH" != main ]; then exit 0; fi)`:               false,
		`sh -c '[ "$CI_COMMIT_BRANCH" = main ] || exit 0'`:                    false,
		`skip() { [ "$CI_COMMIT_BRANCH" = main ] || exit 0; }`:                false,
		`if [ -f skip ]; then [ "$CI_COMMIT_BRANCH" = main ] || exit 0; fi`:   false,
		`# if [ "$CI_COMMIT_BRANCH" != "main" ]; then exit 0; fi`:             false,
		`echo 'if [ "$CI_COMMIT_BRANCH" != main ]; then exit 0; fi' > c.sh`:   false,
		`if [ $CI_COMMIT_BRANCH != main ]; then exit 0; fi`:                   false,
		`[ $CI_COMMIT_BRANCH = main ] || exit 0`:                              true,
		`true || [ -n "$CI_COMMIT_TAG" ] || exit 0`:                           false,
	} {
		if got := exitGuardAt(text) >= 0; got != want {
			t.Errorf("exitGuardAt(%q) >= 0 = %v, want %v", text, got, want)
		}
	}
}

func TestStripShellKeywords(t *testing.T) {
	for in, want := range map[string]string{
		"then   else X=1": "X=1",
		"do X=1":          "X=1",
		"thenX=1":         "thenX=1",
		"  Y=2":           "Y=2",
	} {
		if got := stripShellKeywords(in); got != want {
			t.Errorf("stripShellKeywords(%q) = %q, want %q", in, got, want)
		}
	}
}
