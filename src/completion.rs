//! Static shell completion for the management CLI; it never reads managed state.
use std::collections::BTreeSet;
const COMMANDS: &[&str] = &[
    "adapter",
    "bootstrap",
    "completion",
    "controller",
    "diagnostics",
    "diff",
    "doctor",
    "evidence",
    "execute-apply",
    "execute-recovery",
    "explain",
    "impact",
    "plan",
    "preview-apply",
    "preview-recovery",
    "profile",
    "request-apply",
    "request-recovery",
    "rollout",
    "show",
    "simulate",
    "submit-plan",
    "template",
    "trial",
    "validate",
    "verify-receipt",
];
pub fn candidates(tokens: &[String]) -> Vec<&'static str> {
    if tokens.is_empty() {
        return COMMANDS.to_vec();
    }
    let partial = tokens.last().map(String::as_str).unwrap_or("");
    let prior = &tokens[..tokens.len() - 1];
    let path = prior
        .iter()
        .map(String::as_str)
        .filter(|v| !v.is_empty() && !v.starts_with('-'))
        .collect::<Vec<_>>();
    let choices: &[&str] = if partial.starts_with('-') {
        &["--help", "--json", "--version"]
    } else {
        match path.as_slice() {
            [] => COMMANDS,
            ["show"] => &["active-policies", "effective-policy", "stored-policies"],
            ["explain"] => &["decision"],
            ["template"] => &["list", "render", "show"],
            ["impact"] => &["preview"],
            ["bootstrap"] => &["assess", "export", "proposal"],
            ["rollout"] => &[
                "accept-partial",
                "assess-drift",
                "create",
                "drift-status",
                "pause",
                "propose-reconcile",
                "reconcile-target",
                "resume",
                "retry-target",
                "run-batch",
                "status",
                "validate",
            ],
            _ => &[],
        }
    };
    choices
        .iter()
        .copied()
        .filter(|v| v.starts_with(partial))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
pub fn script(input: &str) -> Result<String, String> {
    let shell = if input == "pwsh" { "powershell" } else { input };
    let s=match shell {
 "bash"=>"_iicp_management_complete() {\n  COMPREPLY=()\n  local -a args=(\"${COMP_WORDS[@]:1:$COMP_CWORD}\")\n  while IFS= read -r candidate; do COMPREPLY+=(\"$candidate\"); done < <(command iicp-management __complete \"${args[@]}\")\n}\ncomplete -F _iicp_management_complete iicp-management\n",
 "zsh"=>"_iicp_management_complete() {\n  local -a args candidates\n  args=(\"${words[@]:1}\")\n  candidates=(\"${(@f)$(command iicp-management __complete \"${args[@]}\")}\")\n  compadd -- $candidates\n}\ncompdef _iicp_management_complete iicp-management\n",
 "fish"=>"function __iicp_management_complete\n  set -l tokens (commandline -opc)\n  set -e tokens[1]\n  set -a tokens (commandline -ct)\n  command iicp-management __complete $tokens\nend\ncomplete -c iicp-management -f -a '(__iicp_management_complete)'\n",
 "powershell"=>"Register-ArgumentCompleter -Native -CommandName iicp-management -ScriptBlock {\n  param($wordToComplete, $commandAst, $cursorPosition)\n  $tokens = @($commandAst.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text })\n  if ($tokens.Count -eq 0 -or $commandAst.Extent.Text.EndsWith(' ')) { $tokens += '' }\n  iicp-management __complete @tokens | ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }\n}\n",
 _=>return Err(format!("unsupported shell: {input}"))};
    Ok(s.into())
}
