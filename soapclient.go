package soapclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"reflect"
	"time"

	"golang.org/x/time/rate"

	log "github.com/sirupsen/logrus"

	"github.com/mitchellh/mapstructure"
)

const (
	libraryVersion    = "0.1"
	headerUserAgent   = "scopesoap/" + libraryVersion
	headerAccept      = "text/xml;"
	headerContentType = "text/xml;;charset=UTF-8"
)

// Client SOAP client
type Client struct {
	// HTTP client
	client *http.Client

	// Base URL for API requests.
	url string
	uri string

	// Rate Limiter
	limiter *rate.Limiter
	
	ErrorCount   int

	// Verbose flag
	PrintReqResp bool
}

type Response http.Response

type RespEnvelope struct {
	XMLName xml.Name
	Body    Body
}

type Body struct {
	XMLName xml.Name
	Fault   Fault
}

// Fault is soap Fault struct
type Fault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`
	Code    string   `xml:"faultcode,omitempty"`
	String  string   `xml:"faultstring,omitempty"`
	Actor   string   `xml:"faultactor,omitempty"`
	Detail  string   `xml:"detail,omitempty"`
}

// NewRateLimitedClient return soap/http cleint with rate limit on
func NewRateLimitedClient(url string, uri string, events, bursts int) *Client {
	c := NewClient(url, uri)
	limit := rate.Limit(events)
	c.limiter = rate.NewLimiter(limit, bursts)
	return c
}

// NewClient return soap/http cleint
func NewClient(url string, uri string) *Client {

	// You need to setup a http.Transport and http.Client timeout or it will eventually hang
	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
	}

	cookieJar, _ := cookiejar.New(nil)

	// Setup the client
	return &Client{
		client: &http.Client{
			Timeout:   time.Second * 10,
			Transport: netTransport,
			Jar:       cookieJar, // Will manage the authentication tokens
		},
		url: url,
		uri: uri,
	}
}

func (c *Client) SetIgnoreCertValidation(ignore bool) error {
	netTransport, ok := c.client.Transport.(*http.Transport)
	if ok {
		netTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: ignore}
	} else {
		return fmt.Errorf("Failed to SetIgnoreCertValidation.")
	}
	return nil
}

// Authenticate to the API and store the token for sending in the header
func (c *Client) Auth(username string, password string) error {

	// c.Auth_Token = ""

	type AuthInfo struct {
		Username string `xml:"username"`
		Password string `xml:"password"`
	}

	var authInfo = AuthInfo{
		Username: username,
		Password: password,
	}

	_, err := c.Call("authenticate", authInfo)
	if err != nil {
		return err
	}

	return nil
}

// Call SOAP client API call
func (c *Client) Call(soapActionName string, request interface{}) (*Response, error) {

	if c.limiter.Allow() == false {
		return nil, fmt.Error("client request limit reached, try again after some delay")
	}

	// Build envelope
	buffer := new(bytes.Buffer)
	encoder := xml.NewEncoder(buffer)

	// Create the envelope
	envelopeStart := xml.StartElement{
		Name: xml.Name{Local: "Envelope"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: "http://schemas.xmlsoap.org/soap/envelope/"}},
	}
	encoder.EncodeToken(envelopeStart)

	// Create the body
	bodyStart := xml.StartElement{
		Name: xml.Name{Local: "Body"},
	}
	encoder.EncodeToken(bodyStart)

	// Encode the action with the payload
	soapAction := xml.StartElement{
		Name: xml.Name{Local: soapActionName},
	}
	// If there is no request data, just encode it as a blank string (otherwise it will skip the action)
	if request == nil {
		request = ""
	}
	encoder.EncodeElement(request, soapAction)

	// End the body
	bodyEnd := xml.EndElement{
		Name: xml.Name{Local: "Body"},
	}
	encoder.EncodeToken(bodyEnd)

	// End the envelope
	envelopeEnd := xml.EndElement{
		Name: xml.Name{Local: "Envelope"},
	}
	encoder.EncodeToken(envelopeEnd)

	// Flush the output
	encoder.Flush()

	// PrintReqResp stuff
	if c.PrintReqResp {
		var buf []byte
		buf, _ = ioutil.ReadAll(buffer)
		buffer = bytes.NewBuffer(buf)
		log.Info("REQUEST:\n", string(buf), "DONE\n")
	}

	req, err := http.NewRequest("POST", c.url, buffer)
	if err != nil {
		return nil, fmt.Errorf("Could not create request. Error:%v", err)
	}
	req.Header.Add("Content-Type", headerContentType)
	req.Header.Set("SOAPAction", c.uri+"#"+soapActionName)
	req.Header.Set("User-Agent", headerUserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		if soapActionName != "authenticate" {
			c.ErrorCount++
		}
		return nil, fmt.Errorf("Failed to send request. Error:%v", err)yy
	}

	c.ErrorCount = 0

	if c.PrintReqResp && err == nil {
		var buf []byte
		buf, _ = ioutil.ReadAll(resp.Body)
		resp.Body = ioutil.NopCloser(bytes.NewReader(buf))
		log.Info("RESPONSE\n", string(buf), "DONE")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, getSoapFault(resp)
	}

	respResponse := Response(*resp)
	return &respResponse, nil
}

func getSoapFault(resp *http.Response) error {
	soapFault, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to read response. Error:%v", err)
	}
	envelope := &RespEnvelope{}
	err = xml.Unmarshal(soapFault, envelope)
	if err != nil {
		return fmt.Errorf("Failed to read response. Error:%v", err)
	}
	return errors.New(envelope.Body.Fault.String)
}

func (resp *Response) Decode(target *interface{}) error {

	decoder := xml.NewDecoder(resp.Body)

	// Decode until we get to the return portion of the Soap Envelope
	var token interface{}
	var err error
	for token, err = decoder.Token(); err != io.EOF; token, err = decoder.Token() {
		if token == nil {
			respBody, _ := ioutil.ReadAll(resp.Body)
			return fmt.Errorf("Decode response token error: %s, respBody: %s", err, respBody)
		}

		if reflect.TypeOf(token).Name() == "StartElement" && token.(xml.StartElement).Name.Local == "return" {
			break
		}
	}
	if err == io.EOF {
		fmt.Println("EOF")
		return fmt.Errorf("Never found return token")
	}

	parseElementType := func(start xml.StartElement) string {
		var returnType string
		for _, attr := range start.Attr {
			// fmt.Println("NAME:", attr.Name.Local, "VALUE:", attr.Value)
			if attr.Name.Local == "type" {
				if attr.Value == "xsd:string" {
					returnType = "string"
				} else if attr.Value == "xsd:integer" {
					returnType = "int"
				} else if attr.Value[:9] == "ns1:Array" {
					returnType = "slice"
				} else {
					returnType = "map"
				}
			}
		}
		return returnType
	}

	// Declare our parser
	var parser func(thisType string) interface{}
	parser = func(thisType string) interface{} {
		// fmt.Println("Parsing into ", thisType)

		var ret interface{}
		switch thisType {
		case "map":
			ret = make(map[string]interface{})
		case "slice":
			ret = make([]interface{}, 0)
		}

		var currentType string
		for token, err = decoder.Token(); err != io.EOF; token, err = decoder.Token() {
			switch tok := token.(type) {
			case xml.StartElement:
				currentType = parseElementType(tok)
				switch thisType {
				case "map":
					ret.(map[string]interface{})[tok.Name.Local] = parser(currentType)
				case "slice":
					ret = append(ret.([]interface{}), parser(currentType))
				}
				// fmt.Println("START:", tok, tok.Attr, tok.Name.Local, currentType)
			case xml.EndElement:
				return ret
			case xml.CharData:
				ret = string(tok)
				// fmt.Println("CHAR:", string(tok))
			case xml.Comment:
				// fmt.Println("COMMENT:", tok)
			}
		}
		return ret
	}

	*target = parser(parseElementType(token.(xml.StartElement)))
	return nil
}

// Unmarshal into target
func (resp *Response) Unmarshal(target interface{}) error {

	var out interface{}
	err := resp.Decode(&out)
	if err != nil {
		target = nil
		return err
	}
	return mapstructure.WeakDecode(out, target)
}

// PrettyPrint - Turns most objects into JSON and prints them pretty
func PrettyPrint(x interface{}) {
	b, err := json.MarshalIndent(x, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println(string(b))
}
