using Microsoft.Extensions.Logging.Abstractions;
using Alastor.Core.Events;
using Alastor.Core.Firewall;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Tests;

public sealed class UfwRuleTests
{
    [Theory]
    [InlineData("443/tcp", 443, null, "tcp", null, null, "allow 443/tcp comment alastor")]
    [InlineData("53", 53, null, null, null, null, "allow 53 comment alastor")]
    [InlineData("60000-61000/udp", 60000, 61000, "udp", null, null, "allow 60000:61000/udp comment alastor")]
    [InlineData("5432/tcp from 10.0.0.0/8", 5432, null, "tcp", "10.0.0.0/8", null, "allow from 10.0.0.0/8 to any port 5432 proto tcp comment alastor")]
    [InlineData("22/tcp from 198.51.100.7", 22, null, "tcp", "198.51.100.7", null, "allow from 198.51.100.7 to any port 22 proto tcp comment alastor")]
    [InlineData("9100/tcp on tailscale0", 9100, null, "tcp", null, "tailscale0", "allow in on tailscale0 to any port 9100 proto tcp comment alastor")]
    public void Policy_syntax_parses_and_renders_ufw_arguments(string text, int port, int? end, string? proto, string? from, string? iface, string args)
    {
        Assert.True(UfwRules.TryParse(text, out var rule, out var error), error);
        Assert.Equal(new UfwRule(port, end, proto, from, iface), rule);
        Assert.Equal(args, string.Join(' ', rule!.AddArgs()));
        Assert.Equal("delete " + args, string.Join(' ', rule.DeleteArgs()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("https")]
    [InlineData("60000-61000")]
    [InlineData("443/tcp from")]
    [InlineData("443/tcp from 300.1.1.1")]
    [InlineData("443/tcp to 10.0.0.1")]
    [InlineData("443/tcp on eth0;rm")]
    public void Bad_rules_are_refused(string text)
    {
        Assert.False(UfwRules.TryParse(text, out _, out var error));
        Assert.NotNull(error);
        Assert.Contains(PolicyYaml.Parse($"firewall: {{allow: [\"{text}\"]}}").Issues, i => i.Path == "firewall.allow[0]");
    }

    [Fact]
    public void Show_added_yields_only_our_rules_and_round_trips()
    {
        var rules = UfwRules.ParseShowAdded(Fixture.Read("firewall/ufw-show-added.txt"));
        Assert.Equal([new UfwRule(22, null, "tcp", null, null), new UfwRule(9100, null, "tcp", null, "tailscale0")], rules);
        foreach (var text in new[] { "443/tcp", "53", "60000-61000/udp", "5432/tcp from 10.0.0.0/8", "9100/tcp on tailscale0", "22/tcp from 198.51.100.7 on eth0" })
        {
            UfwRules.TryParse(text, out var r, out _);
            // ufw prints a rule back as the arguments that created it, quoting the comment.
            var printed = "ufw " + string.Join(' ', r!.AddArgs()).Replace("comment alastor", "comment 'alastor'");
            Assert.Equal(r, Assert.Single(UfwRules.ParseShowAdded(printed)));
        }
        Assert.Equal((false, null), UfwRules.ParseStatus(Fixture.Read("firewall/ufw-status.inactive.txt")));
        Assert.Equal((true, "deny"), UfwRules.ParseStatus(Fixture.Read("network/ufw-verbose.open.txt")));
    }

    [Fact]
    public void Policy_validation_keeps_ssh_reachable()
    {
        Assert.Contains(PolicyYaml.Parse("firewall: {ssh: []}").Issues, i => i.Path == "firewall.ssh" && i.Level == IssueLevel.Error);
        Assert.Contains(PolicyYaml.Parse("firewall: {ssh: [\"to 10.0.0.1\"]}").Issues, i => i.Path == "firewall.ssh[0]");
        Assert.Contains(PolicyYaml.Parse("firewall: {manage: true, ssh: [\"on tailscale0\"]}").Issues, i => i.Path == "firewall.ssh" && i.Level == IssueLevel.Warning);
        Assert.Contains(PolicyYaml.Parse("firewall: {defaultIncoming: allow}").Issues, i => i.Path == "firewall.defaultIncoming");
        Assert.DoesNotContain(PolicyYaml.Parse("firewall: {manage: true, ssh: [any, \"from 198.51.100.0/24\"], allow: [\"5432/tcp from 10.0.0.0/8\"]}").Issues,
            i => i.Path.StartsWith("firewall", StringComparison.Ordinal));
    }
}

public sealed class UfwIntegrationTests
{
    private static readonly OsInfo Ubuntu = new("ubuntu", "24.04", "Ubuntu 24.04", DistroFamily.Debian, "x64");

    private static FakeCommandRunner Runner(string addresses = "network/ip-addr.vps.json", bool active = false)
    {
        var runner = new FakeCommandRunner();
        runner.Installed.Clear();
        runner.Installed.UnionWith(["ufw", "sshd", "ip"]);
        runner.On("sshd -T", Fixture.Read("network/sshd-T.default.txt"))
            .On("ip -j addr show", Fixture.Read(addresses))
            .On("ufw show added", Fixture.Read("firewall/ufw-show-added.txt"))
            .On("ufw status verbose", active ? Fixture.Read("network/ufw-verbose.open.txt") : Fixture.Read("firewall/ufw-status.inactive.txt"));
        runner.Fallback = (file, args) => file == "ufw" ? new CommandResult(0, "Rules updated", "") : null;
        return runner;
    }

    private static PolicyDocument Policy(params string[] ssh) => new()
    {
        Firewall = new() { Manage = true, Ssh = ssh.Length == 0 ? null : ssh.ToList(), Allow = ["5432/tcp from 10.0.0.0/8"] },
        Network = new() { AllowPublicPorts = ["80/tcp", "443/tcp"] },
    };

    [Fact]
    public async Task Plans_our_rules_validates_them_and_enables_ufw()
    {
        var runner = Runner();
        var ufw = new UfwIntegration(runner, null, Ubuntu, NullLogger<UfwIntegration>.Instance, TimeProvider.System);
        var plan = await ufw.PlanAsync(new ReconcileRequest(Policy(), "r1"), default);
        // Inactive ufw doesn't print its defaults, so the default is set explicitly before enabling.
        Assert.Equal(["allow 80/tcp", "allow 443/tcp", "allow 5432/tcp from 10.0.0.0/8", "remove 9100/tcp on tailscale0", "default deny incoming", "enable ufw"],
            plan.Changes.Select(c => c.Description));
        Assert.DoesNotContain(plan.Changes, c => c.Description == "allow 22/tcp"); // already there

        var result = await ufw.ApplyAsync(plan, default);
        Assert.True(result.Success, result.Error);
        var ufwCalls = runner.Calls.Where(c => c.StartsWith("ufw ", StringComparison.Ordinal) && !c.StartsWith("ufw show", StringComparison.Ordinal) && !c.StartsWith("ufw status", StringComparison.Ordinal)).ToList();
        Assert.Equal([
            "ufw --dry-run allow 80/tcp comment alastor",
            "ufw --dry-run allow 443/tcp comment alastor",
            "ufw --dry-run allow from 10.0.0.0/8 to any port 5432 proto tcp comment alastor",
            "ufw allow 80/tcp comment alastor",
            "ufw allow 443/tcp comment alastor",
            "ufw allow from 10.0.0.0/8 to any port 5432 proto tcp comment alastor",
            "ufw delete allow in on tailscale0 to any port 9100 proto tcp comment alastor",
            "ufw default deny incoming",
            "ufw --force enable",
        ], ufwCalls);
        Assert.Contains(result.Events, e => e.Kind == EventKinds.ConfigApplied);
    }

    [Fact]
    public async Task A_failed_step_rolls_back_the_ones_before_it()
    {
        var runner = Runner();
        runner.On("ufw --force enable", "", 1, "ERROR: problem running ufw-init");
        var ufw = new UfwIntegration(runner, null, Ubuntu, NullLogger<UfwIntegration>.Instance, TimeProvider.System);
        var result = await ufw.ApplyAsync(await ufw.PlanAsync(new ReconcileRequest(Policy(), "r1"), default), default);
        Assert.False(result.Success);
        Assert.Equal(ConfigState.Rejected, result.State);
        Assert.Contains("problem running ufw-init", result.Error);
        // Undone in reverse: the removed rule comes back, the added ones go.
        var tail = runner.Calls.SkipWhile(c => c != "ufw --force enable").Skip(1).ToList();
        Assert.Equal([
            "ufw allow in on tailscale0 to any port 9100 proto tcp comment alastor",
            "ufw delete allow from 10.0.0.0/8 to any port 5432 proto tcp comment alastor",
            "ufw delete allow 443/tcp comment alastor",
            "ufw delete allow 80/tcp comment alastor",
        ], tail);
    }

    [Fact]
    public async Task Refuses_plans_that_could_lock_ssh_out()
    {
        // SSH only on tailscale0, but this host has no tailscale0.
        var runner = Runner("network/ip-addr.container.json");
        var ufw = new UfwIntegration(runner, null, Ubuntu, NullLogger<UfwIntegration>.Instance, TimeProvider.System);
        var plan = await ufw.PlanAsync(new ReconcileRequest(Policy("on tailscale0"), "r1"), default);
        Assert.Equal(ConfigState.Rejected, plan.ResultingState);
        Assert.Empty(plan.Changes);
        Assert.Contains(plan.Warnings, w => w.Message.Contains("tailscale0, which isn't up", StringComparison.Ordinal));
        var result = await ufw.ApplyAsync(plan, default);
        Assert.False(result.Success);
        Assert.Equal(Severity.High, Assert.Single(result.Events).Severity);
        Assert.DoesNotContain(runner.Calls, c => c.StartsWith("ufw allow", StringComparison.Ordinal) || c.Contains("enable", StringComparison.Ordinal));

        // With tailscale0 present the same policy is fine.
        var ok = await new UfwIntegration(Runner(), null, Ubuntu, NullLogger<UfwIntegration>.Instance, TimeProvider.System)
            .PlanAsync(new ReconcileRequest(Policy("on tailscale0"), "r1"), default);
        Assert.NotEqual(ConfigState.Rejected, ok.ResultingState);
    }

    [Fact]
    public async Task Unmanaged_leaves_every_rule_and_uninstall_keeps_ssh_while_active()
    {
        var runner = Runner(active: true);
        var ufw = new UfwIntegration(runner, null, Ubuntu, NullLogger<UfwIntegration>.Instance, TimeProvider.System);
        var plan = await ufw.PlanAsync(new ReconcileRequest(new PolicyDocument(), "r1"), default);
        Assert.True(plan.IsNoop);
        Assert.False(ufw.IsWanted(new PolicyDocument()));

        await ufw.RemoveManagedStateAsync(default);
        Assert.Contains("ufw delete allow in on tailscale0 to any port 9100 proto tcp comment alastor", runner.Calls);
        Assert.DoesNotContain(runner.Calls, c => c.StartsWith("ufw delete allow 22/tcp", StringComparison.Ordinal));

        var status = await ufw.DetectAsync(default);
        Assert.Equal(("active", "deny"), (status.Details["status"], status.Details["defaultIncoming"]));
        var rhel = await new UfwIntegration(runner, null, new OsInfo("rocky", "9", "Rocky 9", DistroFamily.RedHat, "x64"), NullLogger<UfwIntegration>.Instance, TimeProvider.System).DetectAsync(default);
        Assert.Equal(Availability.Unavailable, rhel.Availability);
    }
}
