// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file at
// https://github.com/protocolbuffers/protobuf-go/blob/v1.36.11/LICENSE

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	gengo "google.golang.org/protobuf/cmd/protoc-gen-go/internal_gengo"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/pluginpb"
)

func main() {
	protogenRunWithPost(protogen.Options{}, func(gen *protogen.Plugin) error {
		// taken from google.golang.org/protobuf/cmd/protoc-gen-go
		for _, f := range gen.Files {
			if f.Generate {
				gengo.GenerateFile(gen, f)
			}
		}
		gen.SupportedFeatures = gengo.SupportedFeatures
		gen.SupportedEditionsMinimum = gengo.SupportedEditionsMinimum
		gen.SupportedEditionsMaximum = gengo.SupportedEditionsMaximum
		return nil
	}, func(cgr *pluginpb.CodeGeneratorResponse) {
		for _, file := range cgr.GetFile() {
			if file.Name == nil {
				panic("got chunked output from protoc-gen-go")
			}
			if file.InsertionPoint != nil {
				panic("got insertion point in file from protoc-gen-go")
			}
			if !strings.HasSuffix(file.GetName(), ".pb.go") {
				panic("got file without .pb.go suffix from protoc-gen-go")
			}
			file.GeneratedCodeInfo = nil

			prefix, isProtoOpaque := strings.CutSuffix(file.GetName(), "_protoopaque.pb.go")
			if !isProtoOpaque {
				prefix = strings.TrimSuffix(file.GetName(), ".pb.go")
			}

			defaultHybrid := defaultHybridFromPrefix(prefix)

			if isProtoOpaque {
				before, after, ok := strings.Cut(file.GetContent(), "//go:build protoopaque\n")
				if !ok {
					panic("got protoopaque file without protoopaque built tag")
				}

				var newContent string
				if defaultHybrid {
					newContent = before + "//go:build teleport_protoopaque\n" + after
				} else {
					newContent = before + "//go:build !teleport_protohybrid\n" + after
				}
				file.Content = &newContent

				newName := prefix + "_protoopaque.pb.go"
				file.Name = &newName
			} else {
				before, after, ok := strings.Cut(file.GetContent(), "//go:build !protoopaque\n")
				if !ok {
					panic("got non-protoopaque file without !protoopaque built tag")
				}

				var newContent string
				if defaultHybrid {
					newContent = before + "//go:build !teleport_protoopaque\n" + after
				} else {
					newContent = before + "//go:build teleport_protohybrid\n" + after
				}
				file.Content = &newContent

				newName := prefix + "_protohybrid.pb.go"
				file.Name = &newName
			}
		}
	})
}

func protogenRunWithPost(opts protogen.Options, f func(*protogen.Plugin) error, post func(*pluginpb.CodeGeneratorResponse)) error {
	// taken from google.golang.org/protobuf/compiler/protogen
	if len(os.Args) > 1 {
		return fmt.Errorf("unknown argument %q (this program should be run by protoc, not directly)", os.Args[1])
	}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	req := &pluginpb.CodeGeneratorRequest{}
	if err := proto.Unmarshal(in, req); err != nil {
		return err
	}
	gen, err := opts.New(req)
	if err != nil {
		return err
	}
	if err := f(gen); err != nil {
		// Errors from the plugin function are reported by setting the
		// error field in the CodeGeneratorResponse.
		//
		// In contrast, errors that indicate a problem in protoc
		// itself (unparsable input, I/O errors, etc.) are reported
		// to stderr.
		gen.Error(err)
	}
	resp := gen.Response()

	if resp.Error == nil {
		post(resp)
	}

	out, err := proto.Marshal(resp)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(out); err != nil {
		return err
	}
	return nil
}

func defaultHybridFromPrefix(prefix string) bool {
	switch prefix {
	// these files should default to the hybrid codegen because code referencing
	// them hasn't been updated yet
	case
		"api/client/proto/event",
		"api/client/proto/inventory",
		"api/client/proto/requestable_roles",
		"api/gen/proto/go/teleport/accessgraph/v1/authorized_key",
		"api/gen/proto/go/teleport/accessgraph/v1/private_key",
		"api/gen/proto/go/teleport/accessgraph/v1/secrets_service",
		"api/gen/proto/go/teleport/accesslist/v1/accesslist_service",
		"api/gen/proto/go/teleport/accesslist/v1/accesslist",
		"api/gen/proto/go/teleport/accessmonitoringrules/v1/access_monitoring_rules_service",
		"api/gen/proto/go/teleport/accessmonitoringrules/v1/access_monitoring_rules",
		"api/gen/proto/go/teleport/appauthconfig/v1/appauthconfig_service",
		"api/gen/proto/go/teleport/appauthconfig/v1/appauthconfig_sessions_service",
		"api/gen/proto/go/teleport/appauthconfig/v1/appauthconfig",
		"api/gen/proto/go/teleport/auditlog/v1/auditlog",
		"api/gen/proto/go/teleport/autoupdate/v1/autoupdate_service",
		"api/gen/proto/go/teleport/autoupdate/v1/autoupdate",
		"api/gen/proto/go/teleport/backendinfo/v1/backendinfo",
		"api/gen/proto/go/teleport/beams/v1/beam_service",
		"api/gen/proto/go/teleport/beams/v1/beam",
		"api/gen/proto/go/teleport/clientiprestriction/v1/clientiprestriction_service",
		"api/gen/proto/go/teleport/clientiprestriction/v1/clientiprestriction",
		"api/gen/proto/go/teleport/clusterconfig/v1/access_graph_settings",
		"api/gen/proto/go/teleport/clusterconfig/v1/access_graph",
		"api/gen/proto/go/teleport/clusterconfig/v1/clusterconfig_service",
		"api/gen/proto/go/teleport/crownjewel/v1/crownjewel_service",
		"api/gen/proto/go/teleport/crownjewel/v1/crownjewel",
		"api/gen/proto/go/teleport/dbobject/v1/dbobject_service",
		"api/gen/proto/go/teleport/dbobject/v1/dbobject",
		"api/gen/proto/go/teleport/dbobjectimportrule/v1/dbobjectimportrule_service",
		"api/gen/proto/go/teleport/dbobjectimportrule/v1/dbobjectimportrule",
		"api/gen/proto/go/teleport/decision/v1alpha1/database_access",
		"api/gen/proto/go/teleport/decision/v1alpha1/decision_service",
		"api/gen/proto/go/teleport/decision/v1alpha1/denial_metadata",
		"api/gen/proto/go/teleport/decision/v1alpha1/enforcement_feature",
		"api/gen/proto/go/teleport/decision/v1alpha1/permit_metadata",
		"api/gen/proto/go/teleport/decision/v1alpha1/request_metadata",
		"api/gen/proto/go/teleport/decision/v1alpha1/resource",
		"api/gen/proto/go/teleport/decision/v1alpha1/ssh_access",
		"api/gen/proto/go/teleport/decision/v1alpha1/ssh_identity",
		"api/gen/proto/go/teleport/decision/v1alpha1/ssh_join",
		"api/gen/proto/go/teleport/decision/v1alpha1/tls_identity",
		"api/gen/proto/go/teleport/delegation/v1/delegation_session_resource",
		"api/gen/proto/go/teleport/delegation/v1/delegation_session_service",
		"api/gen/proto/go/teleport/desktop/v1/tdpb",
		"api/gen/proto/go/teleport/devicetrust/v1/assert",
		"api/gen/proto/go/teleport/devicetrust/v1/authenticate_challenge",
		"api/gen/proto/go/teleport/devicetrust/v1/device_collected_data",
		"api/gen/proto/go/teleport/devicetrust/v1/device_confirmation_token",
		"api/gen/proto/go/teleport/devicetrust/v1/device_enroll_token",
		"api/gen/proto/go/teleport/devicetrust/v1/device_profile",
		"api/gen/proto/go/teleport/devicetrust/v1/device_source",
		"api/gen/proto/go/teleport/devicetrust/v1/device_web_token",
		"api/gen/proto/go/teleport/devicetrust/v1/device",
		"api/gen/proto/go/teleport/devicetrust/v1/devicetrust_service",
		"api/gen/proto/go/teleport/devicetrust/v1/os_type",
		"api/gen/proto/go/teleport/devicetrust/v1/tpm",
		"api/gen/proto/go/teleport/devicetrust/v1/user_certificates",
		"api/gen/proto/go/teleport/discoveryconfig/v1/discoveryconfig_service",
		"api/gen/proto/go/teleport/discoveryconfig/v1/discoveryconfig",
		"api/gen/proto/go/teleport/dynamicwindows/v1/dynamicwindows_service",
		"api/gen/proto/go/teleport/embedding/v1/embedding",
		"api/gen/proto/go/teleport/externalauditstorage/v1/externalauditstorage_service",
		"api/gen/proto/go/teleport/externalauditstorage/v1/externalauditstorage",
		"api/gen/proto/go/teleport/gitserver/v1/git_server_service",
		"api/gen/proto/go/teleport/grpcclientconfig/v1/grpcclientconfig",
		"api/gen/proto/go/teleport/grpcclientconfig/v1/grpcclientconfigservice",
		"api/gen/proto/go/teleport/hardwarekeyagent/v1/hardwarekeyagent_service",
		"api/gen/proto/go/teleport/header/v1/metadata",
		"api/gen/proto/go/teleport/header/v1/resourceheader",
		"api/gen/proto/go/teleport/healthcheckconfig/v1/health_check_config_service",
		"api/gen/proto/go/teleport/healthcheckconfig/v1/health_check_config",
		"api/gen/proto/go/teleport/identitycenter/v1/identitycenter",
		"api/gen/proto/go/teleport/identitycenter/v1/service",
		"api/gen/proto/go/teleport/integration/v1/awsoidc_service",
		"api/gen/proto/go/teleport/integration/v1/awsra_service",
		"api/gen/proto/go/teleport/integration/v1/integration_service",
		"api/gen/proto/go/teleport/inventory/v1/inventory_service",
		"api/gen/proto/go/teleport/issuance/v1/service",
		"api/gen/proto/go/teleport/join/v1/joinservice",
		"api/gen/proto/go/teleport/kube/v1/kube_service",
		"api/gen/proto/go/teleport/kubewaitingcontainer/v1/kubewaitingcontainer_service",
		"api/gen/proto/go/teleport/kubewaitingcontainer/v1/kubewaitingcontainer",
		"api/gen/proto/go/teleport/label/v1/label",
		"api/gen/proto/go/teleport/linuxdesktop/v1/linux_desktop_service",
		"api/gen/proto/go/teleport/linuxdesktop/v1/linux_desktop",
		"api/gen/proto/go/teleport/loginrule/v1/loginrule_service",
		"api/gen/proto/go/teleport/loginrule/v1/loginrule",
		"api/gen/proto/go/teleport/machineid/v1/bot_instance_service",
		"api/gen/proto/go/teleport/machineid/v1/bot_instance",
		"api/gen/proto/go/teleport/machineid/v1/bot_service",
		"api/gen/proto/go/teleport/machineid/v1/bot",
		"api/gen/proto/go/teleport/machineid/v1/federation_service",
		"api/gen/proto/go/teleport/machineid/v1/federation",
		"api/gen/proto/go/teleport/machineid/v1/workload_identity_service",
		"api/gen/proto/go/teleport/notifications/v1/notifications_service",
		"api/gen/proto/go/teleport/notifications/v1/notifications",
		"api/gen/proto/go/teleport/okta/v1/okta_service",
		"api/gen/proto/go/teleport/plugins/v1/plugin_service",
		"api/gen/proto/go/teleport/presence/v1/relay_server",
		"api/gen/proto/go/teleport/presence/v1/service",
		"api/gen/proto/go/teleport/provisioning/v1/provisioning",
		"api/gen/proto/go/teleport/recordingencryption/v1/recording_encryption_service",
		"api/gen/proto/go/teleport/recordingencryption/v1/recording_encryption",
		"api/gen/proto/go/teleport/recordingmetadata/v1/recordingmetadata_service",
		"api/gen/proto/go/teleport/recordingmetadata/v1/recordingmetadata",
		"api/gen/proto/go/teleport/resourceusage/v1/access_requests",
		"api/gen/proto/go/teleport/resourceusage/v1/account_usage_type",
		"api/gen/proto/go/teleport/resourceusage/v1/resourceusage_service",
		"api/gen/proto/go/teleport/samlidp/v1/samlidp",
		"api/gen/proto/go/teleport/scim/v1/scim_service",
		"api/gen/proto/go/teleport/scopes/access/v1/assignment",
		"api/gen/proto/go/teleport/scopes/access/v1/role",
		"api/gen/proto/go/teleport/scopes/access/v1/service",
		"api/gen/proto/go/teleport/scopes/joining/v1/service",
		"api/gen/proto/go/teleport/scopes/joining/v1/token",
		"api/gen/proto/go/teleport/scopes/v1/scopes",
		"api/gen/proto/go/teleport/secreports/v1/secreports_service",
		"api/gen/proto/go/teleport/secreports/v1/secreports",
		"api/gen/proto/go/teleport/sessionsearch/v1/session_search",
		"api/gen/proto/go/teleport/ssh/v1/ssh",
		"api/gen/proto/go/teleport/stableunixusers/v1/stableunixusers",
		"api/gen/proto/go/teleport/subca/v1/cert_authority_override_id",
		"api/gen/proto/go/teleport/subca/v1/cert_authority_override",
		"api/gen/proto/go/teleport/subca/v1/certificate_override_id",
		"api/gen/proto/go/teleport/subca/v1/certificate_override",
		"api/gen/proto/go/teleport/subca/v1/crl",
		"api/gen/proto/go/teleport/subca/v1/csr",
		"api/gen/proto/go/teleport/subca/v1/distinguished_name",
		"api/gen/proto/go/teleport/subca/v1/public_key_hash",
		"api/gen/proto/go/teleport/subca/v1/subca_service",
		"api/gen/proto/go/teleport/summarizer/v1/access_request",
		"api/gen/proto/go/teleport/summarizer/v1/summarizer_service",
		"api/gen/proto/go/teleport/summarizer/v1/summarizer",
		"api/gen/proto/go/teleport/trait/v1/trait",
		"api/gen/proto/go/teleport/transport/v1/transport_service",
		"api/gen/proto/go/teleport/trust/v1/trust_service",
		"api/gen/proto/go/teleport/userloginstate/v1/userloginstate_service",
		"api/gen/proto/go/teleport/userloginstate/v1/userloginstate",
		"api/gen/proto/go/teleport/userprovisioning/v2/statichostuser_service",
		"api/gen/proto/go/teleport/userprovisioning/v2/statichostuser",
		"api/gen/proto/go/teleport/users/v1/users_service",
		"api/gen/proto/go/teleport/usertasks/v1/user_tasks_service",
		"api/gen/proto/go/teleport/usertasks/v1/user_tasks",
		"api/gen/proto/go/teleport/vnet/v1/vnet_config_service",
		"api/gen/proto/go/teleport/vnet/v1/vnet_config",
		"api/gen/proto/go/teleport/workloadcluster/v1/workloadcluster_service",
		"api/gen/proto/go/teleport/workloadcluster/v1/workloadcluster",
		"api/gen/proto/go/teleport/workloadidentity/v1/attrs",
		"api/gen/proto/go/teleport/workloadidentity/v1/issuance_service",
		"api/gen/proto/go/teleport/workloadidentity/v1/join_attrs",
		"api/gen/proto/go/teleport/workloadidentity/v1/resource_service",
		"api/gen/proto/go/teleport/workloadidentity/v1/resource",
		"api/gen/proto/go/teleport/workloadidentity/v1/revocation_resource",
		"api/gen/proto/go/teleport/workloadidentity/v1/revocation_service",
		"api/gen/proto/go/teleport/workloadidentity/v1/sigstore_policy_resource",
		"api/gen/proto/go/teleport/workloadidentity/v1/sigstore_policy_service",
		"api/gen/proto/go/teleport/workloadidentity/v1/sigstore",
		"api/gen/proto/go/teleport/workloadidentity/v1/x509_overrides_service",
		"api/gen/proto/go/teleport/workloadidentity/v1/x509_overrides",
		"api/gen/proto/go/userpreferences/v1/access_graph",
		"api/gen/proto/go/userpreferences/v1/assist",
		"api/gen/proto/go/userpreferences/v1/cluster_preferences",
		"api/gen/proto/go/userpreferences/v1/discover_resource_preferences",
		"api/gen/proto/go/userpreferences/v1/onboard",
		"api/gen/proto/go/userpreferences/v1/sidenav_preferences",
		"api/gen/proto/go/userpreferences/v1/theme",
		"api/gen/proto/go/userpreferences/v1/unified_resource_preferences",
		"api/gen/proto/go/userpreferences/v1/userpreferences",
		"gen/proto/go/accessgraph/v1/session_search",
		"gen/proto/go/accessgraph/v1alpha/access_graph_service",
		"gen/proto/go/accessgraph/v1alpha/aws",
		"gen/proto/go/accessgraph/v1alpha/azure",
		"gen/proto/go/accessgraph/v1alpha/entra",
		"gen/proto/go/accessgraph/v1alpha/events",
		"gen/proto/go/accessgraph/v1alpha/github",
		"gen/proto/go/accessgraph/v1alpha/gitlab",
		"gen/proto/go/accessgraph/v1alpha/graph",
		"gen/proto/go/accessgraph/v1alpha/netiq",
		"gen/proto/go/accessgraph/v1alpha/okta",
		"gen/proto/go/accessgraph/v1alpha/resources",
		"gen/proto/go/teleport/lib/teleterm/auto_update/v1/auto_update_service",
		"gen/proto/go/teleport/lib/teleterm/v1/access_request",
		"gen/proto/go/teleport/lib/teleterm/v1/app",
		"gen/proto/go/teleport/lib/teleterm/v1/auth_settings",
		"gen/proto/go/teleport/lib/teleterm/v1/cluster",
		"gen/proto/go/teleport/lib/teleterm/v1/database",
		"gen/proto/go/teleport/lib/teleterm/v1/gateway",
		"gen/proto/go/teleport/lib/teleterm/v1/kube",
		"gen/proto/go/teleport/lib/teleterm/v1/label",
		"gen/proto/go/teleport/lib/teleterm/v1/server",
		"gen/proto/go/teleport/lib/teleterm/v1/service",
		"gen/proto/go/teleport/lib/teleterm/v1/target_health",
		"gen/proto/go/teleport/lib/teleterm/v1/tshd_events_service",
		"gen/proto/go/teleport/lib/teleterm/v1/usage_events",
		"gen/proto/go/teleport/lib/teleterm/v1/windows_desktop",
		"gen/proto/go/teleport/lib/teleterm/vnet/v1/vnet_service",
		"gen/proto/go/teleport/lib/vnet/diag/v1/diag",
		"gen/proto/go/teleport/lib/vnet/v1/client_application_service",
		"gen/proto/go/teleport/quicpeering/v1alpha/dial",
		"gen/proto/go/teleport/relaypeering/v1alpha/dial",
		"gen/proto/go/teleport/relaytunnel/v1alpha/control",
		"gen/proto/go/teleport/relaytunnel/v1alpha/dial",
		"gen/proto/go/teleport/relaytunnel/v1alpha/discovery_service",
		"gen/proto/go/teleport/storage/local/stableunixusers/v1/stableunixusers",
		"lib/multiplexer/test/ping":
		return true
	default:
		return false
	}
}
