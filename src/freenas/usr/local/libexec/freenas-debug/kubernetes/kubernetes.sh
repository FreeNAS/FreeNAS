#!/bin/sh

kubernetes_opt() { echo k; }
kubernetes_help() { echo "Dump Kubernetes Information"; }
kubernetes_directory() { echo "Kubernetes"; }
kubernetes_func()
{
	
	section_header "Kubernetes Configuration"
	midclt call kubernetes.config | jq .
	section_footer

	k8s_running="$(midclt call kubernetes.validate_k8s_setup false)"
	if [ "$k8s_running" = "True" ]; then
		section_header "k3s kubectl describe nodes"
		k3s kubectl describe nodes
		section_footer

		section_header "k3s kubectl get pods,svc,daemonsets,deployments,statefulset,sc,pvc,ns,job --all-namespaces -o wide"
		k3s kubectl get pods,svc,daemonsets,deployments,statefulset,sc,pvc,ns,job --all-namespaces -o wide
		section_footer

		section_header "k3s kubectl describe deployments --all-namespaces"
		k3s kubectl describe deployments --all-namespaces
		section_footer

		section_header "k3s kubectl describe pods --all-namespaces"
		k3s kubectl describe pods --all-namespaces
		section_footer

		section_header "k3s kubectl describe services --all-namespaces"
		k3s kubectl describe services --all-namespaces
		section_footer

		section_header "k3s kubectl describe statefulset --all-namespaces"
		k3s kubectl describe statefulset --all-namespaces
		section_footer

		section_header "k3s kubectl describe job --all-namespaces"
		k3s kubectl describe job --all-namespaces
		section_footer

		section_header "k3s kubectl describe cronjob --all-namespaces"
		k3s kubectl describe cronjob --all-namespaces
		section_footer

		section_header "k3s kubectl describe daemonsets --all-namespaces"
		k3s kubectl describe daemonsets --all-namespaces
		section_footer

		section_header "docker ps -a"
		docker ps -a
		section_footer

		section_header "docker images -a"
		docker images -a
		section_footer
	fi

	section_header "K3s Logs (last 1000 lines)"
	journalctl -u k3s | tail -n 1000
	section_footer
}
