package audit

import "testing"

func TestExpressionSources(t *testing.T) {
	for _, test := range []struct {
		input string
		want  bool
	}{
		{"echo ${{ github.event.pull_request.title }}", true},
		{"echo ${{ toJSON(GITHUB['event']['issue'] . body) }}", true},
		{"echo ${{ format('literal }} and '' quotes', github.head_ref) }}", true},
		{"echo ${{ toJSON(github.event) }}", true},
		{"echo ${{ github.event.commits[0].message }}", true},
		{"echo ${{ github.event.pull_request.title_suffix }}", false},
		{"echo ${{ 'github.event.issue.body' }} ${{ github.event_name }}", false},
		{"echo ${{ env.PR_TITLE }}", false},
		{"github.event.comment.body", false},
	} {
		if got := expressionSource(test.input, textSources); got != test.want {
			t.Errorf("%q got %t want %t", test.input, got, test.want)
		}
	}
	if !expressionSource("${{ github.event.pull_request.head.sha }}", checkoutSources) ||
		expressionSource("${{ github.event.pull_request.base.sha }}", checkoutSources) {
		t.Fatal("checkout source classification")
	}
}
