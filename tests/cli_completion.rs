use iicp_management_core::completion::{candidates, script};
#[test]
fn candidates_are_static() {
    for (t, w) in [
        (vec![], vec!["completion", "show"]),
        (vec!["sh"], vec!["show"]),
        (
            vec!["show", ""],
            vec!["active-policies", "effective-policy", "stored-policies"],
        ),
        (vec!["explain", ""], vec!["decision"]),
    ] {
        let tokens = t.into_iter().map(String::from).collect::<Vec<_>>();
        let got = candidates(&tokens);
        for x in w {
            assert!(got.contains(&x));
        }
    }
}
#[test]
fn supported_scripts() {
    for shell in ["bash", "zsh", "fish", "powershell", "pwsh"] {
        assert!(script(shell)
            .unwrap()
            .contains("iicp-management __complete"));
    }
}
