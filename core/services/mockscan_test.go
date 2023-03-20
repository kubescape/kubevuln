package services

import (
	"context"
	"reflect"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
)

func TestMockScanService_GenerateSBOM(t *testing.T) {
	type fields struct {
		happy bool
	}
	type args struct {
		in0 context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			fields: fields{
				happy: true,
			},
		},
		{
			name:    "unhappy",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockScanService(tt.fields.happy)
			if err := m.GenerateSBOM(tt.args.in0); (err != nil) != tt.wantErr {
				t.Errorf("GenerateSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMockScanService_Ready(t *testing.T) {
	type fields struct {
		happy bool
	}
	type args struct {
		in0 context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "happy",
			fields: fields{
				happy: true,
			},
			want: true,
		},
		{
			name: "unhappy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockScanService(tt.fields.happy)
			if got := m.Ready(tt.args.in0); got != tt.want {
				t.Errorf("Ready() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMockScanService_ScanCVE(t *testing.T) {
	type fields struct {
		happy bool
	}
	type args struct {
		in0 context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			fields: fields{
				happy: true,
			},
		},
		{
			name:    "unhappy",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockScanService(tt.fields.happy)
			if err := m.ScanCVE(tt.args.in0); (err != nil) != tt.wantErr {
				t.Errorf("ScanCVE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMockScanService_ValidateGenerateSBOM(t *testing.T) {
	type fields struct {
		happy bool
	}
	type args struct {
		ctx context.Context
		in1 domain.ScanCommand
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    context.Context
		wantErr bool
	}{
		{
			name: "happy",
			fields: fields{
				happy: true,
			},
		},
		{
			name:    "unhappy",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockScanService(tt.fields.happy)
			got, err := m.ValidateGenerateSBOM(tt.args.ctx, tt.args.in1)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGenerateSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateGenerateSBOM() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMockScanService_ValidateScanCVE(t *testing.T) {
	type fields struct {
		happy bool
	}
	type args struct {
		ctx context.Context
		in1 domain.ScanCommand
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    context.Context
		wantErr bool
	}{
		{
			name: "happy",
			fields: fields{
				happy: true,
			},
		},
		{
			name:    "unhappy",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockScanService(tt.fields.happy)
			got, err := m.ValidateScanCVE(tt.args.ctx, tt.args.in1)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScanCVE() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateScanCVE() got = %v, want %v", got, tt.want)
			}
		})
	}
}
