package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"golang.org/x/crypto/ssh"
)

func createPrivateKey(bitsize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitsize)
	if err != nil {
		return nil, err
	}

	if err := privateKey.Validate(); err != nil {
		return nil, err
	}

	return privateKey, nil
}

func encodeToPEM(privateKey *rsa.PrivateKey) []byte {
	priv := x509.MarshalPKCS1PrivateKey(privateKey)
	block := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   priv,
	}

	privPEM := pem.EncodeToMemory(&block)
	return privPEM
}

func encodePublicKeyToBytes(privateKey *rsa.PublicKey) ([]byte, error) {
	publicRSAKey, err := ssh.NewPublicKey(privateKey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRSAKey)
	return pubKeyBytes, nil
}

func importKey(ctx context.Context, cfg aws.Config, name string, key []byte, dryrun bool) (string, error) {
	client := ec2.NewFromConfig(cfg)
	output, err := client.ImportKeyPair(ctx, &ec2.ImportKeyPairInput{
		KeyName:           aws.String(name),
		PublicKeyMaterial: key,
		DryRun:            aws.Bool(dryrun),
	})
	if err != nil {
		return "", err
	}

	return aws.ToString(output.KeyPairId), nil
}

func saveInKMS(ctx context.Context, cfg aws.Config, name string, key []byte) (string, error) {
	client := secretsmanager.NewFromConfig(cfg)
	output, err := client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		Description:  aws.String("SSH KEY"),
		SecretString: aws.String(string(key)),
	})
	if err != nil {
		return "", err
	}

	return aws.ToString(output.ARN), nil
}

var (
	fBitSize = flag.Int("bitSize", 4096, "bitsize of the SSH key")
	fName    = flag.String("name", "", "name of the SSH key")
	fDryrun  = flag.Bool("dryrun", false, "dryrun for EC2 keypair")
)

func deleteImportKeyPair(ctx context.Context, cfg aws.Config, keypairId string, dryrun bool) error {
	client := ec2.NewFromConfig(cfg)
	_, err := client.DeleteKeyPair(ctx, &ec2.DeleteKeyPairInput{
		DryRun:    aws.Bool(dryrun),
		KeyPairId: aws.String(keypairId),
	})
	if err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()

	privKey, err := createPrivateKey(*fBitSize)
	if err != nil {
		log.Fatal("private key creationg failed, exiting")
	}
	privKeyBytes := encodeToPEM(privKey)
	pubKey, err := encodePublicKeyToBytes(&privKey.PublicKey)
	if err != nil {
		log.Fatal("public key creation failed, exiting")
	}

	// write to temp

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	keypairID, err := importKey(context.TODO(), cfg, *fName, pubKey, *fDryrun)
	if err != nil {
		log.Fatal("import keypair failed", err)
	}
	fmt.Println("Saved in EC2", keypairID)
	smKeyPairArn, err := saveInKMS(context.TODO(), cfg, *fName, privKeyBytes)
	if err != nil {
		log.Println("delete keypair as we have errors")
		if err := deleteImportKeyPair(context.TODO(), cfg, keypairID, *fDryrun); err != nil {
			log.Println("failed deletion of keypair", err)
		}
		log.Fatal("secretsmanager keypair save failed", err)
	}
	fmt.Println("Saved in Secretsmanager", smKeyPairArn)

}
