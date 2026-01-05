# biscuit-exploration

This is an exploratory analysis of how biscuit tokens are constructed, attenuated, validated, and authorized.

This exploration will be used to help identify whether or not biscuit tokens make sense for use
in Kubernetes to enable attenuation behaviors.

## Setup

### Clone the repo

```sh
git clone github.com/everettraven/biscuit-exploration.git
```

### Build the CLI tool

```sh
go build -o k8s-biscuit .
```

### Generate public and private keys for biscuit token creation/attenuation/validation

```sh
./k8s-biscuit genkey
```

This will produce two files: `biscuit-key.pem` and `biscuit-key.pub`.

## Exploring trivial sample use cases

Common setup for each use case is to have generated a base biscuit token:

```sh
export BISCUIT_TOKEN=$(./k8s-biscuit gentoken)
```

NOTE: For demonstration purposes, and because these aren't being done against a real Kubernetes cluster,
all tokens generated are considered "admin" by the CLI and thus all operations are allowed by default.

### Use Case: Standard authentication (no attenuation)

#### Perform authorization for a request using biscuit token

```sh
./k8s-biscuit authorize --token ${BISCUIT_TOKEN} --resource pods --verb list
```

### Use Case: Attenuate token so that only requests for the namespace `one` are allowed

#### Perform token attenuation

```sh
export ATTENUATED_BISCUIT_TOKEN=$(./k8s-biscuit attenuate --token ${BISCUIT_TOKEN} --namespace one)
```

#### Sample requests

```sh
$ ./k8s-biscuit authorize --token ${ATTENUATED_BISCUIT_TOKEN} --resource pods --verb list

forbidden
```

```sh
$ ./k8s-biscuit authorize --token ${ATTENUATED_BISCUIT_TOKEN} --resource pods --verb list --namespace two

forbidden
```

```sh
$ ./k8s-biscuit authorize --token ${ATTENUATED_BISCUIT_TOKEN} --resource pods --verb list --namespace one

allowed
```

### Use Case: Attenuate token so that only requests to list Pods in the namespace `one` are allowed

#### Perform token attenuation

```sh
export ATTENUATED_BISCUIT_TOKEN=$(./k8s-biscuit attenuate --token ${BISCUIT_TOKEN} --namespace one --resource pods --verb list)
```

#### Sample requests

```sh
$ ./k8s-biscuit authorize --token ${ATTENUATED_BISCUIT_TOKEN} --resource pods --verb list --namespace one

allowed
```

```sh
$ ./k8s-biscuit authorize --token ${ATTENUATED_BISCUIT_TOKEN} --resource pods --verb list --namespace two

forbidden
```

```sh
$ ./k8s-biscuit authorize --token ${ATTENUATED_BISCUIT_TOKEN} --resource pods --verb deletecollection --namespace one

forbidden
```

```sh
$ ./k8s-biscuit authorize --token ${ATTENUATED_BISCUIT_TOKEN} --resource deployments --verb list --namespace one

forbidden
```
