// middleware/generate_proxy.go
//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

var proxyTemplate = template.Must(template.New("proxy").Parse(`
package middleware

import (
	"context"
	arksdk "{{.ArkSdkImportPath}}"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

type ArkClientProxy struct {
	client arksdk.ArkClient
	chain  *Chain
}

func NewArkClientProxy(client arksdk.ArkClient, chain *Chain) arksdk.ArkClient {
	return &ArkClientProxy{client: client, chain: chain}
}

{{range .Methods}}
func (p *ArkClientProxy) {{.Name}}({{.ParamList}}) {{.ReturnSignature}} {
	{{if .HasCtx}}
	{{if .HasArgs}}
	middlewareArgs := []interface{}{ {{.ArgNamesList}} }
	{{.CtxName}} = p.chain.Before({{.CtxName}}, "{{.Name}}", middlewareArgs)
	{{else}}
	{{.CtxName}} = p.chain.Before({{.CtxName}}, "{{.Name}}", nil)
	{{end}}
	{{else}}
	{{if .HasArgs}}
	middlewareArgs := []interface{}{ {{.ArgNamesList}} }
	p.chain.Before(nil, "{{.Name}}", middlewareArgs)
	{{else}}
	p.chain.Before(nil, "{{.Name}}", nil)
	{{end}}
	{{end}}

	{{if .HasReturn}}
	{{if .HasNamedReturns}}
	// Assign to named return variables
	{{if .HasError}}
	{{.ReturnVars}} = p.client.{{.Name}}({{.CallArgs}})
	results := []interface{}{ {{.ReturnVarsListWithoutError}} }
	{{else}}
	{{.ReturnVars}} = p.client.{{.Name}}({{.CallArgs}})
	results := []interface{}{ {{.ReturnVarsList}} }
	{{end}}
	{{if .HasCtx}}
	p.chain.After({{.CtxName}}, "{{.Name}}", results, {{.ErrorVar}})
	{{else}}
	p.chain.After(nil, "{{.Name}}", results, {{.ErrorVar}})
	{{end}}
	return
	{{else}}
	{{.ReturnVars}} := p.client.{{.Name}}({{.CallArgs}})
	results := []interface{}{ {{.ReturnVarsList}} }
	{{if .HasCtx}}
	p.chain.After({{.CtxName}}, "{{.Name}}", results, {{if .HasError}}{{.ErrorVar}}{{else}}nil{{end}})
	{{else}}
	p.chain.After(nil, "{{.Name}}", results, {{if .HasError}}{{.ErrorVar}}{{else}}nil{{end}})
	{{end}}
	return {{.ReturnVars}}
	{{end}}
	{{else}}
	p.client.{{.Name}}({{.CallArgs}})
	{{if .HasCtx}}
	p.chain.After({{.CtxName}}, "{{.Name}}", nil, nil)
	{{else}}
	p.chain.After(nil, "{{.Name}}", nil, nil)
	{{end}}
	{{end}}
}
{{end}}
`))

type Method struct {
	Name                       string
	ParamList                  string
	ArgNamesList               string
	CallArgs                   string
	ReturnSignature            string
	ReturnVars                 string
	ReturnVarsList             string
	ReturnVarsListWithoutError string
	HasArgs                    bool
	HasCtx                     bool
	CtxName                    string
	HasReturn                  bool
	HasError                   bool
	ErrorVar                   string
	HasNamedReturns            bool
}

func main() {
	arkSdkPath := filepath.Join("../../pkg/client-sdk", "ark_sdk.go")
	arkSdkImportPath := "github.com/ark-network/ark/pkg/client-sdk"

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, arkSdkPath, nil, parser.ParseComments)
	if err != nil {
		log.Fatalf("Failed to parse ark_sdk.go: %v", err)
	}

	var arkClientTypeSpec *ast.TypeSpec

	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec := spec.(*ast.TypeSpec)
			if typeSpec.Name.Name == "ArkClient" {
				arkClientTypeSpec = typeSpec
				break
			}
		}
	}

	if arkClientTypeSpec == nil {
		log.Fatal("ArkClient interface not found")
	}

	interfaceType, ok := arkClientTypeSpec.Type.(*ast.InterfaceType)
	if !ok {
		log.Fatal("ArkClient is not an interface")
	}

	methods := []Method{}

	for _, field := range interfaceType.Methods.List {
		for _, name := range field.Names {
			funcType, ok := field.Type.(*ast.FuncType)
			if !ok {
				continue
			}

			method := Method{
				Name: name.Name,
			}

			// Process parameters
			params := []string{}
			argNames := []string{}
			callArgs := []string{}
			hasCtx := false
			ctxName := ""

			if funcType.Params != nil {
				for i, param := range funcType.Params.List {
					paramType := getTypeName(param.Type)
					if len(param.Names) > 0 {
						for _, paramName := range param.Names {
							argName := paramName.Name
							if paramType == "context.Context" && !hasCtx {
								hasCtx = true
								ctxName = argName
							}
							params = append(params, argName+" "+paramType)
							argNames = append(argNames, argName)
							callArgs = append(callArgs, argName)
						}
					} else {
						argName := fmt.Sprintf("arg%d", i)
						if paramType == "context.Context" && !hasCtx {
							hasCtx = true
							ctxName = argName
						}
						params = append(params, argName+" "+paramType)
						argNames = append(argNames, argName)
						callArgs = append(callArgs, argName)
					}
				}
			}

			method.ParamList = strings.Join(params, ", ")
			method.ArgNamesList = strings.Join(argNames, ", ")
			method.CallArgs = strings.Join(callArgs, ", ")
			method.HasCtx = hasCtx
			method.CtxName = ctxName
			method.HasArgs = len(argNames) > 0

			// Process results
			results := []string{}
			returnVars := []string{}
			returnVarsList := []string{}
			returnVarsListWithoutError := []string{}
			resultTypes := []string{}
			hasError := false
			errorVar := ""
			allNamed := true

			if funcType.Results != nil && len(funcType.Results.List) > 0 {
				method.HasReturn = true
				for _, result := range funcType.Results.List {
					resultType := getTypeName(result.Type)
					resultTypes = append(resultTypes, resultType)
					if len(result.Names) > 0 {
						for _, resultName := range result.Names {
							resultVar := resultName.Name
							results = append(results, fmt.Sprintf("%s %s", resultVar, resultType))
							returnVars = append(returnVars, resultVar)
							returnVarsList = append(returnVarsList, resultVar)
							if resultType == "error" {
								hasError = true
								errorVar = resultVar
							} else {
								returnVarsListWithoutError = append(returnVarsListWithoutError, resultVar)
							}
						}
					} else {
						allNamed = false
						resultVar := fmt.Sprintf("ret%d", len(returnVars))
						returnVars = append(returnVars, resultVar)
						returnVarsList = append(returnVarsList, resultVar)
						if resultType == "error" {
							hasError = true
							errorVar = resultVar
						} else {
							returnVarsListWithoutError = append(returnVarsListWithoutError, resultVar)
						}
					}
				}
				method.HasNamedReturns = allNamed
			}

			if method.HasReturn {
				if method.HasNamedReturns {
					// All return values are named
					method.ReturnSignature = "(" + strings.Join(results, ", ") + ")"
				} else if len(resultTypes) == 1 {
					method.ReturnSignature = resultTypes[0]
				} else {
					method.ReturnSignature = "(" + strings.Join(resultTypes, ", ") + ")"
				}
			}

			method.ReturnVars = strings.Join(returnVars, ", ")
			method.ReturnVarsList = strings.Join(returnVarsList, ", ")
			method.ReturnVarsListWithoutError = strings.Join(returnVarsListWithoutError, ", ")
			method.HasError = hasError
			method.ErrorVar = errorVar

			methods = append(methods, method)
		}
	}

	data := struct {
		Methods          []Method
		ArkSdkImportPath string
	}{
		Methods:          methods,
		ArkSdkImportPath: arkSdkImportPath,
	}

	var buf bytes.Buffer
	err = proxyTemplate.Execute(&buf, data)
	if err != nil {
		log.Fatalf("Failed to execute template: %v", err)
	}

	src, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatalf("Failed to format source: %v", err)
	}

	err = os.WriteFile("ark_client_proxy.go", src, 0644)
	if err != nil {
		log.Fatalf("Failed to write ark_client_proxy.go: %v", err)
	}
}

func isBuiltinType(typeName string) bool {
	builtInTypes := map[string]struct{}{
		"string":      {},
		"int":         {},
		"int64":       {},
		"int32":       {},
		"uint":        {},
		"uint64":      {},
		"uint32":      {},
		"float64":     {},
		"float32":     {},
		"bool":        {},
		"byte":        {},
		"rune":        {},
		"error":       {},
		"interface{}": {},
	}
	_, ok := builtInTypes[typeName]
	return ok
}

func getTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		if isBuiltinType(t.Name) || t.Name == "error" {
			return t.Name
		}
		return "arksdk." + t.Name
	case *ast.SelectorExpr:
		pkgName := ""
		switch x := t.X.(type) {
		case *ast.Ident:
			pkgName = x.Name
		default:
			pkgName = getTypeName(t.X)
		}
		return pkgName + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + getTypeName(t.X)
	case *ast.ArrayType:
		return "[]" + getTypeName(t.Elt)
	case *ast.MapType:
		keyType := getTypeName(t.Key)
		valueType := getTypeName(t.Value)
		return "map[" + keyType + "]" + valueType
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return "func"
	case *ast.ChanType:
		var dir string
		switch t.Dir {
		case ast.RECV:
			dir = "<-chan "
		case ast.SEND:
			dir = "chan<- "
		default:
			dir = "chan "
		}
		return dir + getTypeName(t.Value)
	case *ast.Ellipsis:
		return "..." + getTypeName(t.Elt)
	default:
		var buf bytes.Buffer
		err := format.Node(&buf, token.NewFileSet(), expr)
		if err != nil {
			panic(err)
		}
		return buf.String()
	}
}
