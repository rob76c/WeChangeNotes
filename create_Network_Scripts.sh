

$ ./network kind

##Create a kind cluster
function kind_init() {
  kind_create
  launch_docker_registry
}


##Create a kind cluster
function kind_create() {
  push_fn  "Creating cluster \"${CLUSTER_NAME}\""

  # prevent the next kind cluster from using the previous Fabric network's enrollments.
  rm -rf $PWD/build

  # todo: always delete?  Maybe return no-op if the cluster already exists?
  kind delete cluster --name $CLUSTER_NAME

  local reg_name=${LOCAL_REGISTRY_NAME}
  local reg_port=${LOCAL_REGISTRY_PORT}
  local ingress_http_port=${NGINX_HTTP_PORT}
  local ingress_https_port=${NGINX_HTTPS_PORT}

  # the 'ipvs'proxy mode permits better HA abilities

  cat <<EOF | kind create cluster --name $CLUSTER_NAME --config=-
---
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
    extraPortMappings:
      - containerPort: 80
        hostPort: ${ingress_http_port}
        protocol: TCP
      - containerPort: 443
        hostPort: ${ingress_https_port}
        protocol: TCP
#networking:
#  kubeProxyMode: "ipvs"

# create a cluster with the local registry enabled in containerd
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:${reg_port}"]

EOF

  # workaround for https://github.com/hyperledger/fabric-samples/issues/550 - pods can not resolve external DNS
  for node in $(kind get nodes);
  do
    docker exec "$node" sysctl net.ipv4.conf.all.route_localnet=1;
  done

  pop_fn
}

function launch_docker_registry() {
  push_fn "Launching container registry \"${LOCAL_REGISTRY_NAME}\" at localhost:${LOCAL_REGISTRY_PORT}"

  # create registry container unless it already exists
  local reg_name=${LOCAL_REGISTRY_NAME}
  local reg_port=${LOCAL_REGISTRY_PORT}
  local reg_interface=${LOCAL_REGISTRY_INTERFACE}

  running="$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)"
  if [ "${running}" != 'true' ]; then
    docker run  \
      --detach  \
      --restart always \
      --name    "${reg_name}" \
      --publish "${reg_interface}:${reg_port}:5000" \
      registry:2
  fi

  # connect the registry to the cluster network
  # (the network may already be connected)
  docker network connect "kind" "${reg_name}" || true

  # Document the local registry
  # https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
  cat <<EOF | kubectl apply -f -
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

  pop_fn
}


function cluster_init() {

  apply_nginx_ingress
  apply_cert_manager

  sleep 2

  wait_for_cert_manager
  wait_for_nginx_ingress
  
  if [ "${STAGE_DOCKER_IMAGES}" == true ]; then
    pull_docker_images
    kind_load_docker_images
  fi
}


function apply_nginx() {
  apply_nginx_ingress
  wait_for_nginx_ingress
}

function apply_nginx_ingress() {
  push_fn "Launching ${CLUSTER_RUNTIME} ingress controller"

  # 1.1.2 static ingress with modifications to enable ssl-passthrough
  # k3s : 'cloud'
  # kind : 'kind'
  # kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.1.2/deploy/static/provider/cloud/deploy.yaml

  kubectl apply -f kube/ingress-nginx-${CLUSTER_RUNTIME}.yaml

  pop_fn
}

function wait_for_nginx_ingress() {
  push_fn "Waiting for ingress controller"

  kubectl wait --namespace ingress-nginx \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/component=controller \
    --timeout=2m

  pop_fn
}

function apply_cert_manager() {
  push_fn "Launching cert-manager"

  # Install cert-manager to manage TLS certificates
  kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.6.1/cert-manager.yaml

  pop_fn
}

function wait_for_cert_manager() {
  push_fn "Waiting for cert-manager"

  kubectl -n cert-manager rollout status deploy/cert-manager
  kubectl -n cert-manager rollout status deploy/cert-manager-cainjector
  kubectl -n cert-manager rollout status deploy/cert-manager-webhook

  pop_fn
}





function kind_load_docker_images() {
  push_fn "Loading docker images to KIND control plane"

  kind load docker-image ${FABRIC_CONTAINER_REGISTRY}/fabric-ca:$FABRIC_CA_VERSION
  kind load docker-image ${FABRIC_CONTAINER_REGISTRY}/fabric-orderer:$FABRIC_VERSION
  kind load docker-image ${FABRIC_PEER_IMAGE}
  kind load docker-image couchdb:3.2.1

  kind load docker-image ghcr.io/hyperledger/fabric-rest-sample:latest
  kind load docker-image redis:6.2.5

  pop_fn
}


############################################################1








./network up

function network_up() {

  # Kube config
  init_namespace
  init_storage_volumes
  load_org_config

  # Service account permissions for the k8s builder
  if [ "${CHAINCODE_BUILDER}" == "k8s" ]; then
    apply_k8s_builder_roles
    apply_k8s_builders
  fi

  # Network TLS CAs
  init_tls_cert_issuers

  # Network ECert CAs
  launch_ECert_CAs
  enroll_bootstrap_ECert_CA_users

  # Test Network
  create_local_MSP

  launch_orderers
  launch_peers
}

function init_namespace() {
  local namespaces=$(echo "$ORG0_NS $ORG1_NS $ORG2_NS" | xargs -n1 | sort -u)
  for ns in $namespaces; do
    push_fn "Creating namespace \"$ns\""
    kubectl create namespace $ns || true
    pop_fn
  done
}


##NETWORK FILE:
context FABRIC_VERSION                2.5
context FABRIC_CA_VERSION             1.5

context CLUSTER_RUNTIME               kind                  # or k3s for Rancher
context CONTAINER_CLI                 docker                # or nerdctl for containerd
context CONTAINER_NAMESPACE           ""                    # or "--namespace k8s.io" for containerd / nerdctl

context FABRIC_CONTAINER_REGISTRY     hyperledger
context FABRIC_PEER_IMAGE             ${FABRIC_CONTAINER_REGISTRY}/fabric-peer:${FABRIC_VERSION}
context NETWORK_NAME                  test-network
context CLUSTER_NAME                  kind
context KUBE_NAMESPACE                ${NETWORK_NAME}
context NS                            ${KUBE_NAMESPACE}
context ORG0_NS                       ${NS}
context ORG1_NS                       ${NS}
context ORG2_NS                       ${NS}
context DOMAIN                        localho.st
context CHANNEL_NAME                  mychannel
context ORDERER_TIMEOUT               10s                   # see https://github.com/hyperledger/fabric/issues/3372
context TEMP_DIR                      ${PWD}/build
context CHAINCODE_BUILDER             ccaas                 # see https://github.com/hyperledgendary/fabric-builder-k8s/blob/main/docs/TEST_NETWORK_K8S.md
context K8S_CHAINCODE_BUILDER_IMAGE   ghcr.io/hyperledger-labs/fabric-builder-k8s/k8s-fabric-peer
context K8S_CHAINCODE_BUILDER_VERSION 0.11.0 # For Fabric v2.5+, 0.11.0 or later should be specified

context LOG_FILE                      network.log
context DEBUG_FILE                    network-debug.log
context LOG_ERROR_LINES               2
context LOCAL_REGISTRY_NAME           kind-registry
context LOCAL_REGISTRY_INTERFACE      127.0.0.1
context LOCAL_REGISTRY_PORT           5000
context STAGE_DOCKER_IMAGES           false
context NGINX_HTTP_PORT               80
context NGINX_HTTPS_PORT              443

context RCAADMIN_USER                 rcaadmin
context RCAADMIN_PASS                 rcaadminpw



function init_storage_volumes() {
  push_fn "Provisioning volume storage"

  # Both KIND and k3s use the Rancher local-path provider.  In KIND, this is installed
  # as the 'standard' storage class, and in Rancher as the 'local-path' storage class.
  if [ "${CLUSTER_RUNTIME}" == "kind" ]; then
    export STORAGE_CLASS="standard"

  elif [ "${CLUSTER_RUNTIME}" == "k3s" ]; then
    export STORAGE_CLASS="local-path"

  else
    echo "Unknown CLUSTER_RUNTIME ${CLUSTER_RUNTIME}"
    exit 1
  fi

  cat kube/pvc-fabric-org0.yaml | envsubst | kubectl -n $ORG0_NS create -f - || true
  cat kube/pvc-fabric-org1.yaml | envsubst | kubectl -n $ORG1_NS create -f - || true
  cat kube/pvc-fabric-org2.yaml | envsubst | kubectl -n $ORG2_NS create -f - || true

  pop_fn
}


function load_org_config() {
  push_fn "Creating fabric config maps"

  kubectl -n $ORG0_NS delete configmap org0-config || true
  kubectl -n $ORG1_NS delete configmap org1-config || true
  kubectl -n $ORG2_NS delete configmap org2-config || true

  kubectl -n $ORG0_NS create configmap org0-config --from-file=config/org0
  kubectl -n $ORG1_NS create configmap org1-config --from-file=config/org1
  kubectl -n $ORG2_NS create configmap org2-config --from-file=config/org2

  pop_fn
}

function apply_k8s_builder_roles() {
  push_fn "Applying k8s chaincode builder roles"

  apply_template kube/fabric-builder-role.yaml $ORG1_NS
  apply_template kube/fabric-builder-rolebinding.yaml $ORG1_NS

  pop_fn
}

function apply_k8s_builders() {
  push_fn "Installing k8s chaincode builders"

  apply_template kube/org1/org1-install-k8s-builder.yaml $ORG1_NS
  apply_template kube/org2/org2-install-k8s-builder.yaml $ORG2_NS

  kubectl -n $ORG1_NS wait --for=condition=complete --timeout=60s job/org1-install-k8s-builder
  kubectl -n $ORG2_NS wait --for=condition=complete --timeout=60s job/org2-install-k8s-builder

  pop_fn
}


# experimental: create TLS CA issuers using cert-manager for each org.
function init_tls_cert_issuers() {
  push_fn "Initializing TLS certificate Issuers"

  # Create a self-signing certificate issuer / root TLS certificate for the blockchain.
  # TODO : Bring-Your-Own-Key - allow the network bootstrap to read an optional ECDSA key pair for the TLS trust root CA.
  kubectl -n $ORG0_NS apply -f kube/root-tls-cert-issuer.yaml
  kubectl -n $ORG0_NS wait --timeout=30s --for=condition=Ready issuer/root-tls-cert-issuer
  kubectl -n $ORG1_NS apply -f kube/root-tls-cert-issuer.yaml
  kubectl -n $ORG1_NS wait --timeout=30s --for=condition=Ready issuer/root-tls-cert-issuer
  kubectl -n $ORG2_NS apply -f kube/root-tls-cert-issuer.yaml
  kubectl -n $ORG2_NS wait --timeout=30s --for=condition=Ready issuer/root-tls-cert-issuer

  # Use the self-signing issuer to generate three Issuers, one for each org.
  kubectl -n $ORG0_NS apply -f kube/org0/org0-tls-cert-issuer.yaml
  kubectl -n $ORG1_NS apply -f kube/org1/org1-tls-cert-issuer.yaml
  kubectl -n $ORG2_NS apply -f kube/org2/org2-tls-cert-issuer.yaml

  kubectl -n $ORG0_NS wait --timeout=30s --for=condition=Ready issuer/org0-tls-cert-issuer
  kubectl -n $ORG1_NS wait --timeout=30s --for=condition=Ready issuer/org1-tls-cert-issuer
  kubectl -n $ORG2_NS wait --timeout=30s --for=condition=Ready issuer/org2-tls-cert-issuer

  pop_fn
}


function launch_ECert_CAs() {
  push_fn "Launching Fabric CAs"

  apply_template kube/org0/org0-ca.yaml $ORG0_NS
  apply_template kube/org1/org1-ca.yaml $ORG1_NS
  apply_template kube/org2/org2-ca.yaml $ORG2_NS

  kubectl -n $ORG0_NS rollout status deploy/org0-ca
  kubectl -n $ORG1_NS rollout status deploy/org1-ca
  kubectl -n $ORG2_NS rollout status deploy/org2-ca

  # todo: this papers over a nasty bug whereby the CAs are ready, but sporadically refuse connections after a down / up
  sleep 5

  pop_fn
}


function enroll_bootstrap_ECert_CA_users() {
  push_fn "Enrolling bootstrap ECert CA users"

  enroll_bootstrap_ECert_CA_user org0 $ORG0_NS
  enroll_bootstrap_ECert_CA_user org1 $ORG1_NS
  enroll_bootstrap_ECert_CA_user org2 $ORG2_NS

  pop_fn
}

function enroll_bootstrap_ECert_CA_user() {
  local org=$1
  local ns=$2

  # Determine the CA information and TLS certificate
  CA_NAME=${org}-ca
  CA_DIR=${TEMP_DIR}/cas/${CA_NAME}
  mkdir -p ${CA_DIR}

  # Read the CA's TLS certificate from the cert-manager CA secret
  echo "retrieving ${CA_NAME} TLS root cert"
  kubectl -n $ns get secret ${CA_NAME}-tls-cert -o json \
    | jq -r .data.\"ca.crt\" \
    | base64 -d \
    > ${CA_DIR}/tlsca-cert.pem

  # Enroll the root CA user
  fabric-ca-client enroll \
    --url https://${RCAADMIN_USER}:${RCAADMIN_PASS}@${CA_NAME}.${DOMAIN}:${NGINX_HTTPS_PORT} \
    --tls.certfiles $TEMP_DIR/cas/${CA_NAME}/tlsca-cert.pem \
    --mspdir $TEMP_DIR/enrollments/${org}/users/${RCAADMIN_USER}/msp
}


function create_local_MSP() {
  push_fn "Creating local node MSP"

  create_orderer_local_MSP org0 orderer1
  create_orderer_local_MSP org0 orderer2
  create_orderer_local_MSP org0 orderer3

  create_peer_local_MSP org1 peer1 $ORG1_NS
  create_peer_local_MSP org1 peer2 $ORG1_NS

  create_peer_local_MSP org2 peer1 $ORG2_NS
  create_peer_local_MSP org2 peer2 $ORG2_NS

  pop_fn
}


function create_orderer_local_MSP() {
  local org=$1
  local orderer=$2
  local csr_hosts=${org}-${orderer}

  create_node_local_MSP orderer $org $orderer $csr_hosts $ORG0_NS
}

# Each network node needs a registration, enrollment, and MSP config.yaml
function create_node_local_MSP() {
  local node_type=$1
  local org=$2
  local node=$3
  local csr_hosts=$4
  local ns=$5
  local id_name=${org}-${node}
  local id_secret=${node_type}pw
  local ca_name=${org}-ca

  # Register the node admin
  rc=0
  fabric-ca-client  register \
    --id.name       ${id_name} \
    --id.secret     ${id_secret} \
    --id.type       ${node_type} \
    --url           https://${ca_name}.${DOMAIN}:${NGINX_HTTPS_PORT} \
    --tls.certfiles $TEMP_DIR/cas/${ca_name}/tlsca-cert.pem \
    --mspdir        $TEMP_DIR/enrollments/${org}/users/${RCAADMIN_USER}/msp \
    || rc=$?        # trap error code from registration without exiting the network driver script"

  if [ $rc -eq 1 ]; then
    echo "CA admin was (probably) previously registered - continuing"
  fi

  # Enroll the node admin user from within k8s.  This will leave the certificates available on a volume share in the
  # cluster for access by the nodes when launching in a container.
  cat <<EOF | kubectl -n ${ns} exec deploy/${ca_name} -i -- /bin/sh

  set -x
  export FABRIC_CA_CLIENT_HOME=/var/hyperledger/fabric-ca-client
  export FABRIC_CA_CLIENT_TLS_CERTFILES=/var/hyperledger/fabric/config/tls/ca.crt

  fabric-ca-client enroll \
    --url https://${id_name}:${id_secret}@${ca_name} \
    --csr.hosts ${csr_hosts} \
    --mspdir /var/hyperledger/fabric/organizations/${node_type}Organizations/${org}.example.com/${node_type}s/${id_name}.${org}.example.com/msp

  # Create local MSP config.yaml
  echo "NodeOUs:
    Enable: true
    ClientOUIdentifier:
      Certificate: cacerts/${org}-ca.pem
      OrganizationalUnitIdentifier: client
    PeerOUIdentifier:
      Certificate: cacerts/${org}-ca.pem
      OrganizationalUnitIdentifier: peer
    AdminOUIdentifier:
      Certificate: cacerts/${org}-ca.pem
      OrganizationalUnitIdentifier: admin
    OrdererOUIdentifier:
      Certificate: cacerts/${org}-ca.pem
      OrganizationalUnitIdentifier: orderer" > /var/hyperledger/fabric/organizations/${node_type}Organizations/${org}.example.com/${node_type}s/${id_name}.${org}.example.com/msp/config.yaml
EOF
}

function create_peer_local_MSP() {
  local org=$1
  local peer=$2
  local ns=$3
  local csr_hosts=localhost,${org}-${peer},${org}-peer-gateway-svc

  create_node_local_MSP peer $org $peer $csr_hosts ${ns}
}


function launch_orderers() {
  push_fn "Launching orderers"

  apply_template kube/org0/org0-orderer1.yaml $ORG0_NS
  apply_template kube/org0/org0-orderer2.yaml $ORG0_NS
  apply_template kube/org0/org0-orderer3.yaml $ORG0_NS

  kubectl -n $ORG0_NS rollout status deploy/org0-orderer1
  kubectl -n $ORG0_NS rollout status deploy/org0-orderer2
  kubectl -n $ORG0_NS rollout status deploy/org0-orderer3

  pop_fn
}

function launch_peers() {
  push_fn "Launching peers"

  apply_template kube/org1/org1-peer1.yaml $ORG1_NS
  apply_template kube/org1/org1-peer2.yaml $ORG1_NS
  apply_template kube/org2/org2-peer1.yaml $ORG2_NS
  apply_template kube/org2/org2-peer2.yaml $ORG2_NS

  kubectl -n $ORG1_NS rollout status deploy/org1-peer1
  kubectl -n $ORG1_NS rollout status deploy/org1-peer2
  kubectl -n $ORG2_NS rollout status deploy/org2-peer1
  kubectl -n $ORG2_NS rollout status deploy/org2-peer2

  pop_fn
}




##########################################################

$ ./network channel create




elif [ "${MODE}" == "channel" ]; then
  channel_command_group $@



function channel_command_group() {
  # set -x

  COMMAND=$1
  shift

  if [ "${COMMAND}" == "create" ]; then
    log "Creating channel \"${CHANNEL_NAME}\":"
    channel_up
    log "🏁 - Channel is ready."

  else
    print_help
    exit 1
  fi
}







function channel_up() {

  register_org_admins
  enroll_org_admins

  create_channel_MSP
  create_genesis_block

  join_channel_orderers
  join_channel_peers
}


function register_org_admins() {
  push_fn "Registering org Admin users"

  register_org_admin org0 org0admin org0adminpw
  register_org_admin org1 org1admin org1adminpw
  register_org_admin org2 org2admin org2adminpw

  pop_fn
}

function register_org_admin() {
  local type=admin
  local org=$1
  local id_name=$2
  local id_secret=$3
  local ca_name=${org}-ca

  echo "Registering org admin $username"

  fabric-ca-client  register \
    --id.name       ${id_name} \
    --id.secret     ${id_secret} \
    --id.type       ${type} \
    --url           https://${ca_name}.${DOMAIN}:${NGINX_HTTPS_PORT} \
    --tls.certfiles $TEMP_DIR/cas/${ca_name}/tlsca-cert.pem \
    --mspdir        $TEMP_DIR/enrollments/${org}/users/${RCAADMIN_USER}/msp \
    --id.attrs      "hf.Registrar.Roles=client,hf.Registrar.Attributes=*,hf.Revoker=true,hf.GenCRL=true,admin=true:ecert,abac.init=true:ecert"
}

function enroll_org_admins() {
  push_fn "Enrolling org Admin users"

  enroll_org_admin orderer  org0 org0admin org0adminpw
  enroll_org_admin peer     org1 org1admin org1adminpw
  enroll_org_admin peer     org2 org2admin org2adminpw

  pop_fn
}

# Enroll the admin client to the local certificate storage folder.
function enroll_org_admin() {
  local type=$1
  local org=$2
  local username=$3
  local password=$4

  echo "Enrolling $type org admin $username"

  ENROLLMENTS_DIR=${TEMP_DIR}/enrollments
  ORG_ADMIN_DIR=${ENROLLMENTS_DIR}/${org}/users/${username}

  # skip the enrollment if the admin certificate is available.
  if [ -f "${ORG_ADMIN_DIR}/msp/keystore/key.pem" ]; then
    echo "Found an existing admin enrollment at ${ORG_ADMIN_DIR}"
    return
  fi

  # Determine the CA information and TLS certificate
  CA_NAME=${org}-ca
  CA_DIR=${TEMP_DIR}/cas/${CA_NAME}

  CA_AUTH=${username}:${password}
  CA_HOST=${CA_NAME}.${DOMAIN}
  CA_PORT=${NGINX_HTTPS_PORT}
  CA_URL=https://${CA_AUTH}@${CA_HOST}:${CA_PORT}

  # enroll the org admin
  FABRIC_CA_CLIENT_HOME=${ORG_ADMIN_DIR} fabric-ca-client enroll \
    --url ${CA_URL} \
    --tls.certfiles ${CA_DIR}/tlsca-cert.pem

  # Construct an msp config.yaml
  CA_CERT_NAME=${CA_NAME}-$(echo $DOMAIN | tr -s . -)-${CA_PORT}.pem

  create_msp_config_yaml ${CA_NAME} ${CA_CERT_NAME} ${ORG_ADMIN_DIR}/msp

  # private keys are hashed by name, but we only support one enrollment.
  # test-network examples refer to this as "server.key", which is incorrect.
  # This is the private key used to endorse transactions using the admin's
  # public key.
  mv ${ORG_ADMIN_DIR}/msp/keystore/*_sk ${ORG_ADMIN_DIR}/msp/keystore/key.pem
}


# create an enrollment MSP config.yaml
function create_msp_config_yaml() {
  local ca_name=$1
  local ca_cert_name=$2
  local msp_dir=$3
  echo "Creating msp config ${msp_dir}/config.yaml with cert ${ca_cert_name}"

  cat << EOF > ${msp_dir}/config.yaml
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/${ca_cert_name}
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/${ca_cert_name}
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/${ca_cert_name}
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/${ca_cert_name}
    OrganizationalUnitIdentifier: orderer
EOF
}


function create_channel_MSP() {
  push_fn "Creating channel MSP"

  create_channel_org_MSP org0 orderer $ORG0_NS
  create_channel_org_MSP org1 peer $ORG1_NS
  create_channel_org_MSP org2 peer $ORG2_NS

  extract_orderer_tls_cert org0 orderer1
  extract_orderer_tls_cert org0 orderer2
  extract_orderer_tls_cert org0 orderer3

  pop_fn
}


function create_channel_org_MSP() {
  local org=$1
  local type=$2
  local ns=$3
  local ca_name=${org}-ca

  ORG_MSP_DIR=${TEMP_DIR}/channel-msp/${type}Organizations/${org}/msp
  mkdir -p ${ORG_MSP_DIR}/cacerts
  mkdir -p ${ORG_MSP_DIR}/tlscacerts

  # extract the CA's signing authority from the CA/cainfo response
  curl -s \
    --cacert ${TEMP_DIR}/cas/${ca_name}/tlsca-cert.pem \
    https://${ca_name}.${DOMAIN}:${NGINX_HTTPS_PORT}/cainfo \
    | jq -r .result.CAChain \
    | base64 -d \
    > ${ORG_MSP_DIR}/cacerts/ca-signcert.pem

  # extract the CA's TLS CA certificate from the cert-manager secret
  kubectl -n $ns get secret ${ca_name}-tls-cert -o json \
    | jq -r .data.\"ca.crt\" \
    | base64 -d \
    > ${ORG_MSP_DIR}/tlscacerts/tlsca-signcert.pem

  # create an MSP config.yaml with the CA's signing certificate
  create_msp_config_yaml ${ca_name} ca-signcert.pem ${ORG_MSP_DIR}
}


# Extract an orderer's TLS signing certificate for inclusion in the channel config block
function extract_orderer_tls_cert() {
  local org=$1
  local orderer=$2
  local ns=$ORG0_NS

  echo "Extracting TLS cert for $org $orderer"

  ORDERER_TLS_DIR=${TEMP_DIR}/channel-msp/ordererOrganizations/${org}/orderers/${org}-${orderer}/tls
  mkdir -p $ORDERER_TLS_DIR/signcerts

  kubectl -n $ns get secret ${org}-${orderer}-tls-cert -o json \
    | jq -r .data.\"tls.crt\" \
    | base64 -d \
    > ${ORDERER_TLS_DIR}/signcerts/tls-cert.pem
}


function create_genesis_block() {
  push_fn "Creating channel genesis block"
  cat ${PWD}/config/org0/configtx-template.yaml | envsubst > ${TEMP_DIR}/configtx.yaml
  FABRIC_CFG_PATH=${TEMP_DIR} \
    configtxgen \
      -profile      TwoOrgsApplicationGenesis \
      -channelID    $CHANNEL_NAME \
      -outputBlock  ${TEMP_DIR}/genesis_block.pb

  # configtxgen -inspectBlock ${TEMP_DIR}/genesis_block.pb

  pop_fn
}

function join_channel_orderers() {
  push_fn "Joining orderers to channel ${CHANNEL_NAME}"

  join_channel_orderer org0 orderer1
  join_channel_orderer org0 orderer2
  join_channel_orderer org0 orderer3

  # todo: readiness / liveiness equivalent for channel?  Needs a little bit to settle before peers can join.
  sleep 10

  pop_fn
}

function join_channel_orderer() {
  local org=$1
  local orderer=$2

  # The client certificate presented in this case is the admin user's enrollment key.  This is a stronger assertion
  # of identity than the Docker Compose network, which transmits the orderer node's TLS key pair directly
  osnadmin channel join \
    --orderer-address ${org}-${orderer}-admin.${DOMAIN}:${NGINX_HTTPS_PORT} \
    --ca-file         ${TEMP_DIR}/channel-msp/ordererOrganizations/${org}/orderers/${org}-${orderer}/tls/signcerts/tls-cert.pem \
    --client-cert     ${TEMP_DIR}/enrollments/${org}/users/${org}admin/msp/signcerts/cert.pem \
    --client-key      ${TEMP_DIR}/enrollments/${org}/users/${org}admin/msp/keystore/key.pem \
    --channelID       ${CHANNEL_NAME} \
    --config-block    ${TEMP_DIR}/genesis_block.pb
}


function join_channel_peers() {
  join_org_peers org1
  join_org_peers org2
}


function join_org_peers() {
  local org=$1
  push_fn "Joining ${org} peers to channel ${CHANNEL_NAME}"

  # Join peers to channel
  join_channel_peer $org peer1
  join_channel_peer $org peer2

  pop_fn
}


function join_channel_peer() {
  local org=$1
  local peer=$2

  export_peer_context $org $peer

  peer channel join \
    --blockpath   ${TEMP_DIR}/genesis_block.pb \
    --orderer     org0-orderer1.${DOMAIN} \
    --connTimeout ${ORDERER_TIMEOUT} \
    --tls         \
    --cafile      ${TEMP_DIR}/channel-msp/ordererOrganizations/org0/orderers/org0-orderer1/tls/signcerts/tls-cert.pem
}



##########################################################



$ ./network chaincode deploy transaction ../asset-transfer-basic/chaincode-external 




if [ "${COMMAND}" == "deploy" ]; then
    log "Deploying chaincode"
    deploy_chaincode $@
    log "🏁 - Chaincode is ready."



# Convenience routine to "do everything" required to bring up a sample CC.
function deploy_chaincode() {
  local cc_name=$1
  local cc_label=$1
  local cc_folder=$(absolute_path $2)
  local temp_folder=$(mktemp -d)
  local cc_package=${temp_folder}/${cc_name}.tgz

  prepare_chaincode_image ${cc_folder} ${cc_name}
  package_chaincode       ${cc_name} ${cc_label} ${cc_package}

  if [ "${CHAINCODE_BUILDER}" == "ccaas" ]; then
    set_chaincode_id      ${cc_package}
    launch_chaincode      ${cc_name} ${CHAINCODE_ID} ${CHAINCODE_IMAGE}
  fi

  activate_chaincode      ${cc_name} ${cc_package}
}


# Prepare a chaincode image for use in a builder package.
# Sets the CHAINCODE_IMAGE environment variable
function prepare_chaincode_image() {
  local cc_folder=$1
  local cc_name=$2

  build_chaincode_image ${cc_folder} ${cc_name}

  if [ "${CLUSTER_RUNTIME}" == "k3s" ]; then
    # For rancher / k3s runtimes, bypass the local container registry and load images directly from the image cache.
    export CHAINCODE_IMAGE=${cc_name}
  else
    # For KIND and k8s-builder environments, publish the image to a local docker registry
    export CHAINCODE_IMAGE=localhost:${LOCAL_REGISTRY_PORT}/${cc_name}
    publish_chaincode_image ${cc_name} ${CHAINCODE_IMAGE}
  fi
}


function build_chaincode_image() {
  local cc_folder=$1
  local cc_name=$2

  push_fn "Building chaincode image ${cc_name}"

  $CONTAINER_CLI build ${CONTAINER_NAMESPACE} -t ${cc_name} ${cc_folder}

  pop_fn
}

# tag a docker image with a new name and publish to a remote container registry
function publish_chaincode_image() {
  local cc_name=$1
  local cc_url=$2
  push_fn "Publishing chaincode image ${cc_url}"

  ${CONTAINER_CLI} tag  ${cc_name} ${cc_url}
  ${CONTAINER_CLI} push ${cc_url}

  pop_fn
}


function package_chaincode() {

  if [ "${CHAINCODE_BUILDER}" == "k8s" ]; then
    package_k8s_chaincode $@

  elif [ "${CHAINCODE_BUILDER}" == "ccaas" ]; then
    package_ccaas_chaincode $@

  else
    log "Unknown CHAINCODE_BUILDER ${CHAINCODE_BUILDER}"
    exit 1
  fi
}

function package_ccaas_chaincode() {
  local cc_name=$1
  local cc_label=$2
  local cc_archive=$3

  local cc_folder=$(dirname $cc_archive)
  local archive_name=$(basename $cc_archive)

  push_fn "Packaging ccaas chaincode ${cc_label}"

  mkdir -p ${cc_folder}

  # Allow the user to override the service URL for the endpoint.  This allows, for instance,
  # local debugging at the 'host.docker.internal' DNS alias.
  local cc_default_address="{{.peername}}-ccaas-${cc_name}:9999"
  local cc_address=${TEST_NETWORK_CHAINCODE_ADDRESS:-$cc_default_address}

  cat << EOF > ${cc_folder}/connection.json
{
  "address": "${cc_address}",
  "dial_timeout": "10s",
  "tls_required": false
}
EOF

  cat << EOF > ${cc_folder}/metadata.json
{
  "type": "ccaas",
  "label": "${cc_label}"
}
EOF

  tar -C ${cc_folder} -zcf ${cc_folder}/code.tar.gz connection.json
  tar -C ${cc_folder} -zcf ${cc_archive} code.tar.gz metadata.json

  rm ${cc_folder}/code.tar.gz

  pop_fn
}


function set_chaincode_id() {
  local cc_package=$1

  cc_sha256=$(shasum -a 256 ${cc_package} | tr -s ' ' | cut -d ' ' -f 1)
  cc_label=$(tar zxfO ${cc_package} metadata.json | jq -r '.label')

  CHAINCODE_ID=${cc_label}:${cc_sha256}
}

function launch_chaincode() {
  local org=org1
  local cc_name=$1
  local cc_id=$2
  local cc_image=$3

  launch_chaincode_service ${org} peer1 ${cc_name} ${cc_id} ${cc_image}
  launch_chaincode_service ${org} peer2 ${cc_name} ${cc_id} ${cc_image}
}

function launch_chaincode_service() {
  local org=$1
  local peer=$2
  local cc_name=$3
  local cc_id=$4
  local cc_image=$5
  push_fn "Launching chaincode container \"${cc_image}\""

  # The chaincode endpoint needs to have the generated chaincode ID available in the environment.
  # This could be from a config map, a secret, or by directly editing the deployment spec.  Here we'll keep
  # things simple by using sed to substitute script variables into a yaml template.
  cat kube/${org}/${org}-cc-template.yaml \
    | sed 's,{{CHAINCODE_NAME}},'${cc_name}',g' \
    | sed 's,{{CHAINCODE_ID}},'${cc_id}',g' \
    | sed 's,{{CHAINCODE_IMAGE}},'${cc_image}',g' \
    | sed 's,{{PEER_NAME}},'${peer}',g' \
    | exec kubectl -n $ORG1_NS apply -f -

  kubectl -n $ORG1_NS rollout status deploy/${org}${peer}-ccaas-${cc_name}

  pop_fn
}


function activate_chaincode() {
  local cc_name=$1
  local cc_package=$2

  set_chaincode_id    ${cc_package}

  install_chaincode   ${cc_package}
  approve_chaincode   ${cc_name} ${CHAINCODE_ID}
  commit_chaincode    ${cc_name}
}


# Package and install the chaincode, but do not activate.
function install_chaincode() {
  local org=org1
  local cc_package=$1

  install_chaincode_for ${org} peer1 ${cc_package}
  install_chaincode_for ${org} peer2 ${cc_package}
}

function install_chaincode_for() {
  local org=$1
  local peer=$2
  local cc_package=$3
  push_fn "Installing chaincode for org ${org} peer ${peer}"

  export_peer_context $org $peer

  peer lifecycle chaincode install $cc_package

  pop_fn
}

# approve the chaincode package for an org and assign a name
function approve_chaincode() {
  local org=org1
  local peer=peer1
  local cc_name=$1
  local cc_id=$2
  push_fn "Approving chaincode ${cc_name} with ID ${cc_id}"

  export_peer_context $org $peer

  peer lifecycle \
    chaincode approveformyorg \
    --channelID     ${CHANNEL_NAME} \
    --name          ${cc_name} \
    --version       1 \
    --package-id    ${cc_id} \
    --sequence      1 \
    --orderer       org0-orderer1.${DOMAIN}:${NGINX_HTTPS_PORT} \
    --connTimeout   ${ORDERER_TIMEOUT} \
    --tls --cafile  ${TEMP_DIR}/channel-msp/ordererOrganizations/org0/orderers/org0-orderer1/tls/signcerts/tls-cert.pem

  pop_fn
}

# commit the named chaincode for an org
function commit_chaincode() {
  local org=org1
  local peer=peer1
  local cc_name=$1
  push_fn "Committing chaincode ${cc_name}"

  export_peer_context $org $peer

  peer lifecycle \
    chaincode commit \
    --channelID     ${CHANNEL_NAME} \
    --name          ${cc_name} \
    --version       1 \
    --sequence      1 \
    --orderer       org0-orderer1.${DOMAIN}:${NGINX_HTTPS_PORT} \
    --connTimeout   ${ORDERER_TIMEOUT} \
    --tls --cafile  ${TEMP_DIR}/channel-msp/ordererOrganizations/org0/orderers/org0-orderer1/tls/signcerts/tls-cert.pem

  pop_fn
}



function invoke_chaincode() {
  local cc_name=$1
  shift

  export_peer_context org1 peer1

  peer chaincode invoke \
    -n              $cc_name \
    -C              $CHANNEL_NAME \
    -c              $@ \
    --orderer       org0-orderer1.${DOMAIN}:${NGINX_HTTPS_PORT} \
    --connTimeout   ${ORDERER_TIMEOUT} \
    --tls --cafile  ${TEMP_DIR}/channel-msp/ordererOrganizations/org0/orderers/org0-orderer1/tls/signcerts/tls-cert.pem

  sleep 2
}

#################################################################################################################################

$ ./network chaincode invoke asset-transfer-basic '{"Args":["InitLedger"]}' 

$ ./network chaincode invoke asset-transfer-basic '{"Args":["GetAllTransactions"]}' 

$ ./network chaincode invoke transaction '{"Args":["InitLedger"]}' 

$ ./network chaincode invoke transaction '{"Args":["GetAllTransactions"]}' 



#########################################################################

fabric-ca-client register \
  --id.name robertcarrera \
  --id.secret charlie \
  --id.type user \
  --url https://wechangeappusersadmin:wechangeappusersadminpw@wechangeappusers-ca.localho.st:443 \
  --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/cas/wechangeappusers-ca/tlsca-cert.pem \
  --mspdir /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/enrollments/wechangeappusers/users/rcaadmin/msp


fabric-ca-client  register \
    --id.name       ${id_name} \
    --id.secret     ${id_secret} \
    --id.type       ${type} \
    --url           https://${ca_name}.${DOMAIN}:${NGINX_HTTPS_PORT} \
    --tls.certfiles $TEMP_DIR/cas/${ca_name}/tlsca-cert.pem \
    --mspdir        $TEMP_DIR/enrollments/${org}/users/${RCAADMIN_USER}/msp \
    --id.attrs      "hf.Registrar.Roles=client,hf.Registrar.Attributes=*,hf.Revoker=true,hf.GenCRL=true,admin=true:ecert,abac.init=true:ecert"



## remember to enroll at -u https://wechangeappusers-ca.localho.st:443
FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client register --id.name fscissuer --id.secret password --id.type client --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem

FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client enroll -u https://fscissuer:password@wechangeappusers-ca.localho.st:443 -M "$(pwd)/keys/issuer/fsc/msp" --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem


mv "$(pwd)/keys/issuer/fsc/msp/keystore/"* "$(pwd)/keys/issuer/fsc/msp/keystore/priv_sk"


######################################################################################################################################################################################################################################################

FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client register --id.name alice1 --id.secret password --id.type client --enrollment.type idemix --idemix.curve amcl.Fp256bn --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem
FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client enroll -u https://alice1:password@wechangeappusers-ca.localho.st:443  -M "$(pwd)/keys/owner1/wallet/alice1/msp" --enrollment.type idemix --idemix.curve amcl.Fp256bn --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem

FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client register --id.name bob --id.secret password --id.type client --enrollment.type idemix --idemix.curve amcl.Fp256bn --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem
FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client enroll -u https://bob:password@wechangeappusers-ca.localho.st:443 -M "$(pwd)/keys/owner1/wallet/bob/msp" --enrollment.type idemix --idemix.curve amcl.Fp256bn --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem

FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client register --id.name carlos --id.secret password --id.type client --enrollment.type idemix --idemix.curve amcl.Fp256bn --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem
FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client enroll -u https://carlos:password@wechangeappusers-ca.localho.st:443  -M "$(pwd)/keys/owner2/wallet/carlos/msp" --enrollment.type idemix --idemix.curve amcl.Fp256bn --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem

FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client register --id.name dan --id.secret password --id.type client --enrollment.type idemix --idemix.curve amcl.Fp256bn --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem
FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client enroll -u https://dan:password@wechangeappusers-ca.localho.st:443 -M "$(pwd)/keys/owner2/wallet/dan/msp" --enrollment.type idemix --idemix.curve amcl.Fp256bn --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem
############################################################################################################################################################################################################


tokengen gen dlog --base 300 --exponent 5 --issuers /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/keys/issuer/iss/msp --idemix /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/keys/owner1/wallet/alice --auditors /Users/lemillions/Desktop/WeChangeNetwork13/WeChangeTestNetwork/keys/auditor/aud/msp --output tokenchaincode


./network chaincode deploy tokenchaincode ./tokenchaincode 

function invoke_chaincode() {
  local cc_name=$1
  shift

  export_peer_context wechangeappusers peer1

  peer chaincode invoke \
    -n              $cc_name \
    -C              $CHANNEL_NAME \
    -c              $@ \
    --isInit \
    --orderer       orderer-orderer1.${DOMAIN}:${NGINX_HTTPS_PORT} \
    --connTimeout   ${ORDERER_TIMEOUT} \
    --tls --cafile  ${TEMP_DIR}/channel-msp/ordererOrganizations/orderer/orderers/orderer-orderer1/tls/signcerts/tls-cert.pem

  sleep 2
}






FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client identity list --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem

FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client register --id.name robertcarrera --id.secret charlie --id.type client --id.affiliation wechangeappusers.department1 --id.attrs 'admin=false' --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem

FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client enroll --url https://robertcarrera:charlie@wechangeappusers-ca.localho.st:443 --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem --mspdir /Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/robertcarrera/msp


FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client enroll --url https://wechangeappusersadmin:wechangeappusersadminpw@wechangeappusers-ca.localho.st:443 --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem



robertcarrera --id.secret charlie --type user --affiliation wechangeappusers.department1 --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/cas/wechangeappusers-ca/tlsca-cert.pem

--id.affiliation wechangeappusers.users
--id.affiliation wechangeappusers.support
--id.affiliation wechangeappusers.supportadmin

--id.attrs      "hf.Registrar.Roles=client,hf.Registrar.Attributes=none,hf.Revoker=false,hf.GenCRL=true,admin=false:ecert,abac.init=true:ecert,email=robert@wechangeinc.com,phone=2016268778"



FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork11/test-network-k8s/build/enrollments/wechange/users/wechangeadmin fabric-ca-client identity list --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/cas/wechange-ca/tlsca-cert.pem

FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/enrollments/wechange/users/wechangeadmin fabric-ca-client register --id.name robertcarrera --id.secret charlie --id.type client --id.affiliation wechangeappusers.department1 --id.attrs 'admin=false' --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/cas/wechange-ca/tlsca-cert.pem

##using mspdirectory creates the directory wherever you specify(does not need to be premade) and stores all files related to user there.
FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/enrollments/wechange/users/wechangeadmin fabric-ca-client enroll --url https://robertcarrera:charlie@wechange-ca.localho.st:443 --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/cas/wechange-ca/tlsca-cert.pem --mspdir /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/enrollments/wechange/users/robertcarrera/msp

FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/enrollments/wechange/users/wechangeadmin fabric-ca-client register --id.name robertcarrera2 --id.secret charlie2 --id.type client --id.affiliation wechangeappusers.department1 --id.attrs "hf.Registrar.Roles=client,hf.Registrar.Attributes=none,hf.Revoker=false,hf.GenCRL=true,admin=false:ecert,abac.init=true:ecert,email=robert@wechangeinc.com,phone=2016268778" --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/cas/wechange-ca/tlsca-cert.pem


FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/enrollments/wechange/users/wechangeadmin fabric-ca-client register --id.name robertcarrera3 --id.secret charlie2 --id.type client --id.affiliation wechange.department1 --id.attrs "hf.Registrar.Roles=client,hf.Registrar.Attributes=none,hf.Revoker=false,hf.GenCRL=true,admin=false:ecert,abac.init=true:ecert,email=robert@wechangeinc.com,phone=2016268778" --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/cas/wechange-ca/tlsca-cert.pem


FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/enrollments/wechange/users/wechangeadmin fabric-ca-client enroll --url https://robertcarrera3:charlie2@wechange-ca.localho.st:443 --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/cas/wechange-ca/tlsca-cert.pem --mspdir /Users/lemillions/Desktop/WeChangeNetwork9/test-network-k8s/build/enrollments/wechange/users/robertcarrera/msp









docker run -it -v ${PWD}/server_config:/etc/hyperledger/fabric-ca-server -v /Users/lemillions/Desktop/FabricCA2/fabric-ca/opt/fortanix/pkcs11:/etc/hyperledger/fabric hyperledger/fabric-ca bash





-v /Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/opt/fortanix/pkcs11:/etc/hyperledger/fabric


bccsp:
    default: PKCS11
    PKCS11:
      Library: "/etc/hyperledger/fabric/fortanix_pkcs11_4.8.2070.so"
      hash: SHA2
      security: 256
      Label: "Fortanix Token"
      Pin: file://etc/hyperledger/fabric/fortanix_pkcs11.conf


fabric-ca-client register --id.name robertcarrera --id.type client --id.secret charlie --csr.names
C=es,ST=madrid,L=Madrid,O=wechangeappusers --csr.cn wechangeappusers -m wechangeappusers --id.attrs '"hf.IntermediateCA=true"' -u
http://localhost:7054 --loglevel debug

fabric-ca-client register --id.name robertcarrera --id.type client --id.secret charlie --csr.names
C=es,ST=madrid,L=Madrid,O=wechangeappusers --id.attrs '"hf.IntermediateCA=true"' -u
http://localhost:7054 --loglevel debug

fabric-ca-client register --id.name robertcarrera3 --id.secret charlie2 --id.type client --id.attrs "hf.Registrar.Roles=client,hf.Registrar.Attributes=none,hf.Revoker=false,hf.GenCRL=true,admin=false:ecert,abac.init=true:ecert,email=robert@wechangeinc.com,phone=2016268778"



fabric-ca-client enroll -u http://robertcarrera3:charlie2@localhost:7054

fabric-ca-client enroll -u http://robertcarrera3:charlie2@localhost:7054 --mspdir /etc/hyperledger/robertcarrera3

###########################################################################################################################

kubectl -n wechangeapp exec deploy/wechangeappusers-ca -i -- /bin/sh


vi ~/Library/Group\ Containers/group.com.docker/settings.json

###########################################################################################################################
bccsp:
    default: PKCS11
    PKCS11:
      Library: "/Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/opt/fortanix/pkcs11/fortanix_pkcs11_4.8.2070.so"
      hash: SHA2
      security: 256
      Label: "Fortanix Token"
      Pin: file:///Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/opt/fortanix/pkcs11/fortanix_pkcs11.conf


##############################################################################################################

export TEMP_DIR="/Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build"
mkdir -p "${TEMP_DIR:-/tmp}/softhsm"
echo "directories.tokendir = ${TEMP_DIR:-/tmp}/softhsm" > "${HOME}/softhsm2.conf"
SOFTHSM2_CONF="${HOME}/softhsm2.conf" softhsm2-util --init-token --slot 0 --label "ForFabric" --pin 98765432 --so-pin 1234

##You have to either have a frabric-client-config-hsm file already set or you can use the templete that is generated below, however after it is generated you have to edit the file for pkcs11 support and then enroll the user again.
SOFTHSM2_CONF="{$HOME}/softhsm2.conf" ./scripts/generate-hsm-user.sh HSMUser

## Check if the user was created
FABRIC_CA_CLIENT_HOME=/Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin fabric-ca-client identity list --tls.certfiles /Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/cas/wechangeappusers-ca/tlsca-cert.pem


$ ./network chaincode deploy transaction ../asset-transfer-basic/chaincode-external
$ ./network chaincode invoke transaction '{"Args":["InitLedger"]}'

##Run from the application-go folder(or wherever the hsm-sample application is that has tags pkcs11)
SOFTHSM2_CONF="${HOME}/softhsm2.conf" go run -tags pkcs11 .
##
$ ./network chaincode invoke transaction '{"Args":["GetAllTransactions"]}'


SOFTHSM2_CONF=$HSM2_CONF fabric-ca-client register -c /Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin/fabric-ca-client-config-hsm.yaml --mspdir "/Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin/msp" --id.name "robertcarrera" --id.secret "charlie" --id.type client --caname ca-wechangeappusers --id.maxenrollments 0 -u https://robertcarrera:charlie@wechangeappusers-ca.localho.st:443 --tls.certfiles "$TLS_CERT" && echo user probably already registered, continuing
SOFTHSM2_CONF=$HSM2_CONF  fabric-ca-client enroll -c /Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin/fabric-ca-client-config-hsm.yaml -u https://robertcarrera:charlie@wechangeappusers-ca.localho.st:443 --mspdir "/Users/lemillions/Desktop/WeChangeNetwork11/WeChangeTestNetwork/build/enrollments/wechangeappusers/users/wechangeappusersadmin/msp" --tls.certfiles "$TLS_CERT"


######################################################################################

CreateTransaction(Amount: 50, Location: "23.6935385, -32.8555598", Reciever: "New York Dispensary 2", Sender: "Robert Isaac Carrera", Status: "Pending", Timestamp: "2023-10-15 18:00:23", TransactionID: "5", TransactionPurchase: TransactionPurchase{AmountInGrams: 3.5, AmountInMiligramsOfTotalTHC: 1800, Category: "Flower", Cost: 400, FedTax: 5, Name: "Durban Poison", StateTax: 4, THCPercent: .20, WeFee: 1}, TypeOfTransaction: "PUREPU")

$ ./network chaincode invoke transaction '{"Args":["CreateTransaction",Amount: 50, Location: "23.6935385, -32.8555598", Reciever: "New York Dispensary 2", Sender: "Robert Isaac Carrera", Status: "Pending", Timestamp: "2023-10-15 18:00:23", TransactionID: "5", TransactionPurchase: TransactionPurchase{AmountInGrams: 3.5, AmountInMiligramsOfTotalTHC: 1800, Category: "Flower", Cost: 400, FedTax: 5, Name: "Durban Poison", StateTax: 4, THCPercent: .20, WeFee: 1}, TypeOfTransaction: "PUREPU"]}'

$ ./network chaincode invoke transaction '{"Args":["CreateTransactionPurchase","5", "50", "23.6935385, -32.8555598", "New York Dispensary 2", "Robert Isaac Carrera", "Pending", "2023-10-15 18:00:23", "3.5", "1800", "Flower", "50", "5", "Durban Poison", "4", ".20", "1", "PUREPU"]}'

##########################################################################################################
export PATH=/Users/lemillions/Desktop/WeChangeNetworkToken/fabric-samples/token-sdk/bin:$PATH
export PATH=/Users/lemillions/Desktop/WeChangeNetworkToken/fabric-samples/token-sdk/config:$PATH


##################################################################################


sudo nano /etc/hosts


127.0.0.1 peer1.wechangeappusers.example.com
127.0.0.1 peer1.wechange.example.com
127.0.0.1 orderer.example.com
127.0.0.1 owner1.example.com
127.0.0.1 owner2.example.com
127.0.0.1 auditor.example.com
127.0.0.1 issuer.example.com



##Here are a few things to check:

##Namespace: Make sure you are in the correct namespace or specify the correct namespace in the kubectl command. In your YAML file, it looks like ${ORG2_NS} is used for the namespace. Ensure that the correct value is set for ${ORG2_NS} or replace it with the actual namespace.

##bash
kubectl get secret wechangeappusers-peer1-tls-cert -n <your_namespace> -o jsonpath="{.data['tls\.crt']}" | base64 --decode > tls.crt

##Secret Name: Double-check the secret name. In the YAML file, it's specified as wechangeappusers-peer1-tls-cert. Ensure that it is the correct name.

##Existence: Confirm that the secret exists. You can list all the secrets in the namespace to verify:

##bash
kubectl get secrets -n <your_namespace>


## to view a file in a kubernetes container
kubectl exec -it your-pod-name -c your-container-name /bin/sh

kubectl exec -n wechangeapp -it wechangeappusers-ca-5f745d8d54-jlfrg -c main /bin/sh 
cd folder
##to view file
cat file

###################################################################################################

#To stop process at a port

##On Unix-based Systems (Linux, macOS):

    Open a terminal.

    Run the following command to find the process ID (PID) using port 9000:

    bash

lsof -i :9000

##This will display information about the process using port 9000, including its PID.
##Once you have the PID, you can use the kill command to stop the process. Replace [PID] with the actual PID:
##bash
kill -9 [PID]
##On Windows:
##Open Command Prompt or PowerShell as an administrator.
##Run the following command to find the process using port 9000:
##bash
netstat -ano | findstr :9000

##This will display the process ID (PID) using port 9000.
##Use the following command to stop the process. Replace [PID] with the actual PID:
##bash
taskkill /F /PID [PID]
###################################################################################################

# INIT_REQUIRED="--init-required" ../test-network/network.sh deployCCAAS -ccn tokenchaincode -ccp $(pwd)/tokenchaincode -cci "init" -verbose -ccs 1
#  -cci )
#     CC_INIT_FCN="$2"
#     shift