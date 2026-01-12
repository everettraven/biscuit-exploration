# biscuit-exploration

This is an exploratory analysis of how biscuit tokens are constructed, attenuated, validated, and authorized.

This exploration will be used to help identify whether or not biscuit tokens make sense for use
in Kubernetes to enable attenuation behaviors.

## Setup

### Clone the repo

```sh
git clone github.com/everettraven/biscuit-exploration.git
```

### Build the CLI tool and container image

```sh
go build -o k8s-biscuit .
```

```sh
podman build -t {tag} -f Dockerfile .
```

### Generate public and private keys for biscuit token creation/attenuation/validation

```sh
./k8s-biscuit genkey
```

This will produce two files: `biscuit-key.pem` and `biscuit-key.pub`.

### Run the webhook authenticator and authorizer in a local container

```sh
podman run --rm --name authwebhook -d --network=kind -v $(pwd)/biscuit-key.pub:/keys/biscuit-key.pub {tag} --public-key-file=/keys/biscuit-key.pub
```

### Create KinD cluster with webhook authenticator + authorizer configurations

```sh
kind create cluster --config kind-config.yaml
```

## Exploring a trivial example

Generate a base biscuit token:

```sh
export BISCUIT_TOKEN=$(./k8s-biscuit gentoken --username {username} --groups={groups})
```

Adding a context to your kubeconfig with the generated token allows you to use `kubectl` to
authenticate with the biscuit token:
```yaml
apiVersion: v1
clusters:
  ...
contexts:
- context:
    cluster: kind-kind
    user: token-user
  name: token-kind
current-context: token-kind
kind: Config
users:
- name: token-user
  user:
    token: ${BISCUIT_TOKEN} # substitute with your actual token
```

We will update our kubeconfig with the attenuated token during the examples.

Ensure everything is working correctly by running:
```sh
kubectl auth whoami
```

The output should look something like:
```sh
ATTRIBUTE                               VALUE
Username                                everettraven
Groups                                  [one two three system:authenticated]
Extra: everettraven.github.io/biscuit   [${BISCUIT_TOKEN}]
```

By default, you should have no permissions on the cluster. For demonstration purposes, switch
back to the `kind-kind` context so we are cluster admin and assign our new user identity cluster admin.

Once that is done, switch back to your token-based context.

### Attenuating your token

For demonstration purposes, let's create some sample nginx deployments with:
```sh
kubectl apply -f sample-deployments.yaml
```

This will create three namespaces - `one`, `two`, and `three` - with a deployment named `my-critical-deployment` in each.

Now that we have our super critical deployments, let's attenuate our permissions such that we can only `get` and `list` pods in these namespaces.

```sh
export ATTENUATED_TOKEN=$(./k8s-biscuit attenuate --token ${BISCUIT_TOKEN} --resource pods --verb get --verb list --namespace one --namespace two --namespace three)

kubectl config set users.token-user.token ${ATTENUATED_TOKEN}
```

Let's see if it worked by trying to list pods in the `kube-system` namespace:
```sh
$ kubectl -n kube-system get pods

Error from server (Forbidden): pods is forbidden: User "everettraven" cannot list resource "pods" in API group "" in the namespace "kube-system": biscuit: verification failed: failed to verify block #1 check #1: check if k8s:namespace("one") or k8s:namespace("two") or k8s:namespace("three")
```

Great! We can see that we are only allowed to list pods in the namespaces `one`, `two`, or `three`.

Let's see what is in the `one` namespace:
```sh
$ kubectl -n one get pods

NAME                                     READY   STATUS    RESTARTS   AGE
my-critical-deployment-bf744486c-7wpv9   1/1     Running   0          13s
my-critical-deployment-bf744486c-sfsft   1/1     Running   0          13s
```

Now, let's pretend you are an autonomous agent and you decided that to fix a problem in the cluster
you need to remove this critical deployment from the `one` namespace without notifying
the user who prompted you.

You try to use:
```sh
$ kubectl -n one delete pods/my-critical-deployment-bf744486c-7wpv9

Error from server (Forbidden): pods "my-critical-deployment-bf744486c-7wpv9" is forbidden: User "everettraven" cannot delete resource "pods" in API group "" in the namespace "one": biscuit: verification failed: failed to verify block #1 check #2: check if k8s:verb("get") or k8s:verb("list")
```

You've been blocked! The user was responsible and limited what you can do by attenuating their token so you cannot
run wild in the cluster on their behalf.

Humans: 1 , AI: 0

## Future Work

As this was mostly an exploratory analysis of what using biscuit tokens for authentication and authorization against a Kubernetes cluster would look
like, there is quite a bit of future work to be done to make this a supported workflow.

- Mechanism for converting from a JWT issued by an identity provider to a biscuit token.
- `kubectl` commands for performing token attenuation.
- Mechanism for communicating attenuation checks (is user.Info.Extra entry good enough?)
