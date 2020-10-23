# deny admission to containers which donot have resource limits/ resources specified
# Logical OR rules

package kubernetes.admission

deny[reason] {
    containers := input.spec.template.spec.containers[_]
    # deny if cpu requests are not set
    not cpuRequests(containers)
    # deny if memory requests are not set
    not memoryRequests(containers)
    reason := "Resource requests not set."
}

deny[reason] {
    containers := input.spec.template.spec.containers[_]
    # deny if cpu limits are not set
    not cpuLimits(container)
    # deny if memory limits are not set
    not memoryLimits(container)
    reason := "Resource limits not set."
}

cpuRequests(container) {
    containers.resources.request.cpu
}

memoryRequests(container) {
    containers.resources.request.memory
}

cpuLimits(container) {
    containers.resources.limits.cpu
}

memoryLimits(container) {
    containers.resources.limits.memory
}
