package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	authorizationv1api "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	authorizationapi "k8s.io/kubernetes/pkg/apis/authorization"
	authorizationv1 "k8s.io/kubernetes/pkg/apis/authorization/v1"
	"k8s.io/kubernetes/pkg/registry/authorization/util"
)

func NewAuthorize(authrzr authorizer.Authorizer) *Authorize {
	return &Authorize{
		authorizer: authrzr,
	}
}

type Authorize struct {
	authorizer authorizer.Authorizer
}

func (a *Authorize) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	requestedSARBytes, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("error reading request body: %v\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	requestedSAR := &authorizationv1api.SubjectAccessReview{}
	err = json.Unmarshal(requestedSARBytes, requestedSAR)
	if err != nil {
		log.Printf("error unmarshalling request body: %v\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Println("XXX DEBUG requested SAR user:", string(requestedSAR.Spec.User))

	if strings.Contains(requestedSAR.Spec.User, "biscuit:") {
		fmt.Println("XXX DEBUG requested SAR:", string(requestedSARBytes))
	}

	apiSAR := &authorizationapi.SubjectAccessReview{}
	err = authorizationv1.Convert_v1_SubjectAccessReview_To_authorization_SubjectAccessReview(requestedSAR, apiSAR, nil)
	if err != nil {
		log.Printf("error converting: %v\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	attrsRecord := util.AuthorizationAttributesFrom(apiSAR.Spec)

	responseSAR := &authorizationv1api.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1.SchemeGroupVersion.String(),
			Kind:       "SubjectAccessReview",
		},
	}

	decision, reason, err := a.authorizer.Authorize(req.Context(), attrsRecord)

	log.Println("XXX DEBUG: decision:", decision)
	log.Println("XXX DEBUG: reason:", reason)
	log.Println("XXX DEBUG: error:", err)

	if err != nil {
		log.Println(err)
		responseSAR.Status = authorizationv1api.SubjectAccessReviewStatus{
			Allowed:         false,
			Denied:          true,
			EvaluationError: err.Error(),
		}
	} else {
		switch decision {
		case authorizer.DecisionAllow:
			responseSAR.Status = authorizationv1api.SubjectAccessReviewStatus{
				Allowed: true,
			}
		case authorizer.DecisionNoOpinion:
			responseSAR.Status = authorizationv1api.SubjectAccessReviewStatus{
				Allowed: false,
			}
		case authorizer.DecisionDeny:
			responseSAR.Status = authorizationv1api.SubjectAccessReviewStatus{
				Allowed: false,
				Denied:  true,
				Reason:  reason,
			}
		}
	}

	responseSARBytes, err := json.Marshal(responseSAR)
	if err != nil {
		log.Println(err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Write(responseSARBytes)
}
