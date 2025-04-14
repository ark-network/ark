// Code generated by go-swagger; DO NOT EDIT.

package indexer_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/models"
)

// IndexerServiceGetSweptCommitmentTxReader is a Reader for the IndexerServiceGetSweptCommitmentTx structure.
type IndexerServiceGetSweptCommitmentTxReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IndexerServiceGetSweptCommitmentTxReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIndexerServiceGetSweptCommitmentTxOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewIndexerServiceGetSweptCommitmentTxDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewIndexerServiceGetSweptCommitmentTxOK creates a IndexerServiceGetSweptCommitmentTxOK with default headers values
func NewIndexerServiceGetSweptCommitmentTxOK() *IndexerServiceGetSweptCommitmentTxOK {
	return &IndexerServiceGetSweptCommitmentTxOK{}
}

/*
IndexerServiceGetSweptCommitmentTxOK describes a response with status code 200, with default header values.

A successful response.
*/
type IndexerServiceGetSweptCommitmentTxOK struct {
	Payload *models.V1GetSweptCommitmentTxResponse
}

// IsSuccess returns true when this indexer service get swept commitment tx o k response has a 2xx status code
func (o *IndexerServiceGetSweptCommitmentTxOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this indexer service get swept commitment tx o k response has a 3xx status code
func (o *IndexerServiceGetSweptCommitmentTxOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indexer service get swept commitment tx o k response has a 4xx status code
func (o *IndexerServiceGetSweptCommitmentTxOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this indexer service get swept commitment tx o k response has a 5xx status code
func (o *IndexerServiceGetSweptCommitmentTxOK) IsServerError() bool {
	return false
}

// IsCode returns true when this indexer service get swept commitment tx o k response a status code equal to that given
func (o *IndexerServiceGetSweptCommitmentTxOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the indexer service get swept commitment tx o k response
func (o *IndexerServiceGetSweptCommitmentTxOK) Code() int {
	return 200
}

func (o *IndexerServiceGetSweptCommitmentTxOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/commitmentTx/{txid}/swept][%d] indexerServiceGetSweptCommitmentTxOK %s", 200, payload)
}

func (o *IndexerServiceGetSweptCommitmentTxOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/commitmentTx/{txid}/swept][%d] indexerServiceGetSweptCommitmentTxOK %s", 200, payload)
}

func (o *IndexerServiceGetSweptCommitmentTxOK) GetPayload() *models.V1GetSweptCommitmentTxResponse {
	return o.Payload
}

func (o *IndexerServiceGetSweptCommitmentTxOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1GetSweptCommitmentTxResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIndexerServiceGetSweptCommitmentTxDefault creates a IndexerServiceGetSweptCommitmentTxDefault with default headers values
func NewIndexerServiceGetSweptCommitmentTxDefault(code int) *IndexerServiceGetSweptCommitmentTxDefault {
	return &IndexerServiceGetSweptCommitmentTxDefault{
		_statusCode: code,
	}
}

/*
IndexerServiceGetSweptCommitmentTxDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type IndexerServiceGetSweptCommitmentTxDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this indexer service get swept commitment tx default response has a 2xx status code
func (o *IndexerServiceGetSweptCommitmentTxDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this indexer service get swept commitment tx default response has a 3xx status code
func (o *IndexerServiceGetSweptCommitmentTxDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this indexer service get swept commitment tx default response has a 4xx status code
func (o *IndexerServiceGetSweptCommitmentTxDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this indexer service get swept commitment tx default response has a 5xx status code
func (o *IndexerServiceGetSweptCommitmentTxDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this indexer service get swept commitment tx default response a status code equal to that given
func (o *IndexerServiceGetSweptCommitmentTxDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the indexer service get swept commitment tx default response
func (o *IndexerServiceGetSweptCommitmentTxDefault) Code() int {
	return o._statusCode
}

func (o *IndexerServiceGetSweptCommitmentTxDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/commitmentTx/{txid}/swept][%d] IndexerService_GetSweptCommitmentTx default %s", o._statusCode, payload)
}

func (o *IndexerServiceGetSweptCommitmentTxDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/commitmentTx/{txid}/swept][%d] IndexerService_GetSweptCommitmentTx default %s", o._statusCode, payload)
}

func (o *IndexerServiceGetSweptCommitmentTxDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *IndexerServiceGetSweptCommitmentTxDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
