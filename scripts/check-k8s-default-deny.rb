#!/usr/bin/env ruby
# Checks that the Kubernetes policy templates put a default-deny floor, for
# ingress and egress, in every namespace they write policies for:
#
# * generic profile (every NetworkPolicy outside the Cilium file): a
#   NetworkPolicy with `podSelector: {}`, policyTypes Ingress and Egress and
#   no ingress or egress rule;
# * Cilium profile (cilium-mandatory-enforcement.yaml): a
#   CiliumNetworkPolicy with `endpointSelector: {}` and exactly one empty
#   rule (`- {}`) in both `ingress` and `egress`. An empty or omitted list
#   does not enable default-deny in Cilium.
#
# Each profile must also cover the namespaces listed in REQUIRED.
#
# Usage: scripts/check-k8s-default-deny.rb [directory] (default:
# deploy/kubernetes). Exits 1 and names each namespace without a floor.
require "yaml"

REQUIRED = %w[praetore-agents praetore-gateway praetore-tools praetore-egress praetore-sandbox].freeze
CILIUM_FILE = "cilium-mandatory-enforcement.yaml"

dir = ARGV.fetch(0, "deploy/kubernetes")
generic = Hash.new { |hash, key| hash[key] = [] }
cilium = Hash.new { |hash, key| hash[key] = [] }
Dir.glob(File.join(dir, "*.yaml")).sort.each do |path|
  YAML.load_stream(File.read(path)).compact.each do |doc|
    namespace = doc.dig("metadata", "namespace")
    case doc["kind"]
    when "NetworkPolicy" then generic[namespace] << doc["spec"]
    when "CiliumNetworkPolicy"
      if File.basename(path) != CILIUM_FILE
        abort "#{path}: CiliumNetworkPolicy outside #{CILIUM_FILE}"
      end
      cilium[namespace] << doc["spec"]
    end
  end
end

def generic_floor?(spec)
  spec["podSelector"] == {} &&
    spec.fetch("policyTypes", []).sort == %w[Egress Ingress] &&
    [nil, []].include?(spec["ingress"]) && [nil, []].include?(spec["egress"])
end

def cilium_floor?(spec)
  spec["endpointSelector"] == {} && spec["ingress"] == [{}] && spec["egress"] == [{}] &&
    (spec.keys - %w[endpointSelector ingress egress]).empty?
end

problems = []
[["NetworkPolicy", generic, method(:generic_floor?)],
 ["CiliumNetworkPolicy", cilium, method(:cilium_floor?)]].each do |kind, policies, floor|
  (policies.keys | REQUIRED).sort.each do |namespace|
    next if policies[namespace].any? { |spec| floor.call(spec) }
    problems << "#{kind}: namespace #{namespace} has no ingress and egress default-deny policy"
  end
end
if problems.empty?
  puts "default-deny floor in #{REQUIRED.join(', ')} (NetworkPolicy and CiliumNetworkPolicy)"
else
  problems.each { |problem| warn problem }
  exit 1
end
