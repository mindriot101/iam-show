package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/fatih/color"
)

type Fetcher struct {
	client *iam.Client
	w      io.Writer
}

func NewFetcher(client *iam.Client) *Fetcher {
	return &Fetcher{
		client: client,
		w:      os.Stdout,
	}
}

type ArnType string

const (
	RoleArn        ArnType = "role"
	PolicyArn              = "policy"
	AssumedRoleArn         = "assumed-role"
)

func (f *Fetcher) FetchStatements(ctx context.Context, arn string) ([]Statement, error) {
	switch f.arnType(arn) {
	case RoleArn:
		return f.fetchRoleStatements(ctx, arn)
	case AssumedRoleArn:
		return f.fetchAssumedRoleStatements(ctx, arn)
	case PolicyArn:
		return f.fetchPolicyStatements(ctx, arn)
	default:
		return nil, fmt.Errorf("TODO FetchStatements")
	}
}

func (f *Fetcher) arnType(arn string) ArnType {
	if strings.Contains(arn, ":policy/") {
		return PolicyArn
	} else if strings.Contains(arn, ":role/") {
		return RoleArn
	} else if strings.Contains(arn, ":assumed-role/") {
		return AssumedRoleArn
	} else {
		return RoleArn
	}
}

func (f *Fetcher) fetchRoleStatements(ctx context.Context, arn string) ([]Statement, error) {
	roleName, err := f.getRoleName(arn)
	if err != nil {
		return nil, fmt.Errorf("getting role name: %w", err)
	}
	return f.getStatementsForRole(ctx, roleName)
}

func (f *Fetcher) getRoleName(arn string) (string, error) {
	parts := strings.Split(arn, "/")
	nParts := len(parts)
	switch nParts {
	case 2, 3:
		return parts[1], nil
	default:
		return "", fmt.Errorf("invalid arn format: %s", arn)
	}
}

func (f *Fetcher) getStatementsForRole(ctx context.Context, roleName string) ([]Statement, error) {
	allStatements := []Statement{}

	// attached policies

	// TODO: print assume role policy document
	res, err := f.client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("getting role policies for %s: %w", roleName, err)
	}

	for _, policy := range res.AttachedPolicies {
		arn := *policy.PolicyArn
		statements, err := f.FetchStatements(ctx, arn)
		if err != nil {
			return nil, fmt.Errorf("fetching policy statements for %s: %w", *policy.PolicyName, err)
		}
		for _, statement := range statements {
			allStatements = append(allStatements, statement)
		}
	}

	// role policies
	rolePoliciesRes, err := f.client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("listing inline role policies")
	}
	for _, policyName := range rolePoliciesRes.PolicyNames {
		policyRes, err := f.client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			PolicyName: aws.String(policyName),
			RoleName:   aws.String(roleName),
		})
		if err != nil {
			continue
		}

		statements, err := decodeDocument(*policyRes.PolicyDocument)
		if err != nil {
			return nil, fmt.Errorf("could not parse policy document: %w", err)
		}

		for _, statement := range statements {
			allStatements = append(allStatements, statement)
		}
	}

	return allStatements, nil
}

func decodeDocument(document string) ([]Statement, error) {
	document, err := url.PathUnescape(document)
	if err != nil {
		return nil, fmt.Errorf("invalid policy document: %w", err)
	}

	var policy RawPolicy
	if err := json.Unmarshal([]byte(document), &policy); err != nil {
		return nil, fmt.Errorf("decoding document: %w", err)
	}

	return policy.Statement, nil
}

func (f *Fetcher) fetchAssumedRoleStatements(ctx context.Context, arn string) ([]Statement, error) {
	roleName, err := f.getRoleName(arn)
	if err != nil {
		return nil, fmt.Errorf("getting role name: %w", err)
	}
	return f.getStatementsForRole(ctx, roleName)
}

func (f *Fetcher) fetchPolicyStatements(ctx context.Context, arn string) ([]Statement, error) {
	// fetch policy details and get default version
	res, err := f.client.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: aws.String(arn),
	})
	if err != nil {
		return nil, fmt.Errorf("getting policy: %w", err)
	}
	versionP := res.Policy.DefaultVersionId
	if versionP == nil {
		return nil, fmt.Errorf("could not get policy version")
	}
	version := *versionP
	_ = version

	// fetch policy version information
	versionRes, err := f.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(arn),
		VersionId: aws.String(version),
	})
	if err != nil {
		return nil, fmt.Errorf("getting policy version: %w", err)
	}
	policyVersion := *versionRes.PolicyVersion
	if policyVersion.Document == nil {
		return nil, fmt.Errorf("no document found")
	}
	statements, err := decodeDocument(*policyVersion.Document)
	if err != nil {
		return nil, fmt.Errorf("could not parse policy document: %w", err)
	}
	return statements, nil
}

type Action string
type Resource string

type RawPolicy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Action []Action `json:"Action"`
	// Resource []Resource `json:"Resource"`
	Resource DynamicResource `json:"Resource"`
	Effect   string          `json:"Effect"`
}

type DynamicResource struct {
	Resources []string
}

func (d *DynamicResource) UnmarshalJSON(data []byte) error {
	resources := []string{}
	if err := json.Unmarshal(data, &resources); err != nil {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("unmarshalling resources: %w", err)
		}

		d.Resources = append(d.Resources, s)
	} else {
		d.Resources = resources
	}

	return nil
}

func joinActions(actions []Action) string {
	yellow := color.New(color.FgYellow).SprintFunc()
	s := []string{}
	for _, action := range actions {
		s = append(s, yellow(string(action)))
	}
	return strings.Join(s, ", ")
}

func (s Statement) Present(w io.Writer) {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()

	var effect string
	switch s.Effect {
	case "Allow":
		effect = green(s.Effect)
	case "Deny":
		effect = red(s.Effect)
	default:
		effect = s.Effect
	}

	for _, resource := range s.Resource.Resources {
		fmt.Fprintf(w, "%s %s to %s\n", effect, joinActions(s.Action), blue(resource))
	}
}

func main() {

	// flags
	arnFlag := flag.String("arn", "", "arn of managed policy or role")
	flag.Parse()

	if *arnFlag == "" {
		log.Fatal("missing arn")
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-west-2"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	ctx := context.TODO()

	client := iam.NewFromConfig(cfg)
	fetcher := NewFetcher(client)
	statements, err := fetcher.FetchStatements(ctx, *arnFlag)
	if err != nil {
		log.Fatal(err)
	}

	for _, statement := range statements {
		statement.Present(os.Stdout)
	}
}
