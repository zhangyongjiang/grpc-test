package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	testpb "github.com/zhangyongjiang/grpc-test/grpc_demo"
	"encoding/pem"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"crypto/rand"
)

var timeout = time.Second * 5

//test server to be registered with the GRPCServer
type testServiceServer struct{}

func (tss *testServiceServer) EmptyCall(ctx context.Context, msg *testpb.Empty) (*testpb.Empty, error) {
	return new(testpb.Empty), nil
}

//invoke the EmptyCall RPC
func invokeEmptyCall(address string, dialOptions []grpc.DialOption) (*testpb.Empty, error) {
	//add DialOptions
	dialOptions = append(dialOptions, grpc.WithBlock())
	dialOptions = append(dialOptions, grpc.WithTimeout(timeout))
	//create GRPC client conn
	clientConn, err := grpc.Dial(address, dialOptions...)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer clientConn.Close()

	//create GRPC client
	client := testpb.NewTestServiceClient(clientConn)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	//invoke service
	empty, err := client.EmptyCall(ctx, new(testpb.Empty))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return empty, nil
}

//utility function for testing client / server communication using TLS
func runMutualAuth(port string,  config  testpb.SecureServerConfig,  clientTlsConfig *tls.Config) error {

	//loop through all the test servers

		//create listener
		listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
		if err != nil {
			fmt.Println(err)
			return err
		}

		//create GRPCServer
		var serverOpts []grpc.ServerOption
		srv, err := testpb.NewGRPCServerFromListener(config, serverOpts)
		if err != nil {
			fmt.Println(err)
			return err
		}

		//register the GRPC test server and start the GRPCServer
		testpb.RegisterTestServiceServer(srv.Server(), &testServiceServer{})
		go srv.Server().Serve(listener)
		defer srv.Stop()
		//should not be needed but just in case
		time.Sleep(10 * time.Millisecond)

			//invoke the EmptyCall service
			address := fmt.Sprintf("%s:%s", "ctn", port)
			_, err = invokeEmptyCall(address,
				[]grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(clientTlsConfig))})
			//we expect success from trusted clients
			if err != nil {
				fmt.Printf("Trusted client test failed: %s\n", err)
				return err
			} else {
				fmt.Printf("Trusted client successfully connected to %s\n", address)
			}


	return nil
}


func main() {
	serverKeyPEM, serverCertPEM, _ := GenerateRandomEcdsaKeyPair()
	clientKeyPEM, clientCertPEM, _ := GenerateRandomEcdsaKeyPair()

	clientCert, _ := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	clientTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		InsecureSkipVerify:true,
	}

	runMutualAuth(
		"9876",

		testpb.SecureServerConfig{
			UseTLS:            true,
			ServerCertificate: serverCertPEM,
			ServerKey:         serverKeyPEM,
			RequireClientCert: false,
		},

		clientTlsConfig)
}


func GenerateRandomEcdsaKeyPair() (keyPem []byte, certPem []byte, err error) {
	commonName := "ctn"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	keyPem = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})


	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	//basic template to use
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour), //~ten years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,
											  x509.ExtKeyUsageClientAuth}

	//set the organization for the subject
	subject := pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
	subject.Organization = []string{commonName}
	//hardcode to localhost for hostname verification
	subject.CommonName = commonName
	template.Subject = subject

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	return keyPem, certPem, nil
}
