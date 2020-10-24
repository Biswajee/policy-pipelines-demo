# deny admission to containers which donot have resource limits/ resources specified
# Logical OR rules

package kubernetes.admission

deny[reason] {
    containers := input.spec.template.spec.containers[_]
    # deny if cpu requests are not set
    not cpurequests(containers)
    # deny if memory requests are not set
    not memoryrequests(containers)
    reason := "Resource requests not set."
}

deny[reason] {
    containers := input.spec.template.spec.containers[_]
    # deny if cpu limits are not set
    not cpulimits(containers)
    # deny if memory limits are not set
    not memorylimits(containers)
    reason := "Resource limits not set."
}

cpurequests(containers) {
    containers.resources.requests.cpu
}

memoryrequests(containers) {
    containers.resources.requests.memory
}

cpulimits(containers) {
    containers.resources.limits.cpu
}

memorylimits(containers) {
    containers.resources.limits.memory
}
