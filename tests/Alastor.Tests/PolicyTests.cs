using Alastor.Core.Policy;

namespace Alastor.Tests;

public class PolicyTests
{
    private static string DefaultPolicy => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "default.yaml"));

    [Fact]
    public void Default_policy_is_valid()
    {
        var r = PolicyYaml.Parse(DefaultPolicy);
        Assert.True(r.IsValid, string.Join("; ", r.Issues.Select(i => $"{i.Path}: {i.Message}")));
        Assert.Equal("fail2ban", r.Document!.Banning!.Engine);
        Assert.True(r.Document.Banning.Jails!["sshd"].Enabled);
    }

    [Fact]
    public void Unknown_keys_are_errors_with_a_line_number()
    {
        var r = PolicyYaml.Parse("banning:\n  defaults:\n    maxretires: 3\n");
        Assert.False(r.IsValid);
        var issue = Assert.Single(r.Issues);
        Assert.Equal(3, issue.Line);
        Assert.Contains("maxretires", issue.Message);
    }

    [Theory]
    [InlineData("banning:\n  defaults:\n    bantime: 5 parsecs\n", "banning.defaults.bantime")]
    [InlineData("banning:\n  defaults:\n    findtime: permanent\n", "banning.defaults.findtime")]
    [InlineData("banning:\n  defaults:\n    maxretry: 0\n", "banning.defaults.maxretry")]
    [InlineData("banning:\n  engine: snort\n", "banning.engine")]
    [InlineData("banning:\n  allowlist: [10.0.0.0/33]\n", "banning.allowlist[0]")]
    [InlineData("banning:\n  jails:\n    alastor-manual: {enabled: true}\n", "banning.jails.alastor-manual")]
    [InlineData("banning:\n  jails:\n    'bad name': {enabled: true}\n", "banning.jails.bad name")]
    [InlineData("banning:\n  defaults:\n    filter: sshd\n", "banning.defaults.")]
    public void Invalid_values_are_reported_at_their_path(string yaml, string path)
    {
        var r = PolicyYaml.Parse(yaml);
        Assert.False(r.IsValid);
        Assert.Contains(r.Issues, i => i.Level == IssueLevel.Error && i.Path == path);
    }

    [Theory]
    // Anything that could smuggle a new INI line or section into the rendered jail.d file must be rejected.
    [InlineData("banning:\n  defaults:\n    banaction: \"nftables\\n[sshd]\\nenabled = false\"\n")]
    [InlineData("banning:\n  jails:\n    sshd:\n      enabled: true\n      logpath: \"/var/log/auth.log\\nignoreip = 0.0.0.0/0\"\n")]
    [InlineData("banning:\n  jails:\n    sshd:\n      enabled: true\n      port: \"ssh\\naction = x\"\n")]
    public void Ini_injection_attempts_are_rejected(string yaml) => Assert.False(PolicyYaml.Parse(yaml).IsValid);

    [Fact]
    public void Warns_about_lockout_risks()
    {
        var r = PolicyYaml.Parse("banning:\n  jails:\n    sshd: {enabled: true, maxretry: 1}\n");
        Assert.True(r.IsValid);
        Assert.Contains(r.Issues, i => i.Level == IssueLevel.Warning && i.Path == "banning.allowlist");
        Assert.Contains(r.Issues, i => i.Level == IssueLevel.Warning && i.Path == "banning.jails.sshd.maxretry");
    }

    [Fact]
    public void Layers_merge_global_then_group_then_host_with_allowlist_union()
    {
        var global = PolicyYaml.Parse(DefaultPolicy).Document!;
        var group = PolicyYaml.Parse("banning:\n  allowlist: [10.0.0.0/8]\n  defaults: {bantime: 2h}\n  jails:\n    nginx-http-auth: {enabled: true}\n").Document!;
        var host = PolicyYaml.Parse("banning:\n  allowlist: [192.0.2.1]\n  jails:\n    sshd: {maxretry: 3}\n").Document!;
        var merged = PolicyMerger.MergeLayers([global, group, host]);

        Assert.Equal("2h", merged.Banning!.Defaults!.Bantime);         // group overrides global
        Assert.Equal("10m", merged.Banning.Defaults.Findtime);          // untouched global value survives
        Assert.True(merged.Banning.Jails!["sshd"].Enabled);             // global
        Assert.Equal(3, merged.Banning.Jails["sshd"].Maxretry);         // host adds to the same jail
        Assert.True(merged.Banning.Jails["nginx-http-auth"].Enabled);   // group-only jail
        Assert.Equal(["10.0.0.0/8", "192.0.2.1"], merged.Banning.Allowlist);
        Assert.Equal("24h", merged.Agent!.OfflineGracePeriod);
    }

    [Fact]
    public void Revision_is_independent_of_key_order_and_changes_with_content()
    {
        var a = PolicyYaml.Parse("banning:\n  allowlist: [1.1.1.1, 2.2.2.2]\n  jails:\n    a: {enabled: true}\n    b: {enabled: false}\n").Document!;
        var b = PolicyYaml.Parse("banning:\n  jails:\n    b: {enabled: false}\n    a: {enabled: true}\n  allowlist: [2.2.2.2, 1.1.1.1]\n").Document!;
        var c = PolicyYaml.Parse("banning:\n  jails:\n    b: {enabled: true}\n    a: {enabled: true}\n").Document!;
        Assert.Equal(PolicyYaml.Revision(a), PolicyYaml.Revision(b));
        Assert.NotEqual(PolicyYaml.Revision(a), PolicyYaml.Revision(c));
    }

    [Theory]
    [InlineData("90s", 90)]
    [InlineData("10m", 600)]
    [InlineData("1h", 3600)]
    [InlineData("7d", 604800)]
    [InlineData("2w", 1209600)]
    [InlineData("3600", 3600)]
    [InlineData("permanent", -1)]
    public void Durations(string input, long seconds)
    {
        Assert.True(Duration.TryParseSeconds(input, out var s));
        Assert.Equal(seconds, s);
    }

    [Fact]
    public void Json_roundtrip_preserves_the_document()
    {
        var doc = PolicyYaml.Parse(DefaultPolicy).Document!;
        var back = PolicyYaml.FromJson(PolicyYaml.ToJson(doc))!;
        Assert.Equal(PolicyYaml.Revision(doc), PolicyYaml.Revision(back));
    }
}
