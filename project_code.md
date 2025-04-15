# workspace 代码库

*通过 combine_code.py 自动生成*

## 目录

- [.golangci.yml](#-golangci-yml)
- [.goreleaser.yaml](#-goreleaser-yaml)
- [Dockerfile](#Dockerfile)
- [LICENSE](#LICENSE)
- [cmd/github-mcp-server/main.go](#cmd-github-mcp-server-main-go)
- [cmd/mcpcurl/main.go](#cmd-mcpcurl-main-go)
- [combine.py](#combine-py)
- [conformance/conformance_test.go](#conformance-conformance_test-go)
- [go.mod](#go-mod)
- [go.sum](#go-sum)
- [pkg/github/code_scanning.go](#pkg-github-code_scanning-go)
- [pkg/github/code_scanning_test.go](#pkg-github-code_scanning_test-go)
- [pkg/github/context_tools.go](#pkg-github-context_tools-go)
- [pkg/github/context_tools_test.go](#pkg-github-context_tools_test-go)
- [pkg/github/dynamic_tools.go](#pkg-github-dynamic_tools-go)
- [pkg/github/helper_test.go](#pkg-github-helper_test-go)
- [pkg/github/issues.go](#pkg-github-issues-go)
- [pkg/github/issues_test.go](#pkg-github-issues_test-go)
- [pkg/github/pullrequests.go](#pkg-github-pullrequests-go)
- [pkg/github/pullrequests_test.go](#pkg-github-pullrequests_test-go)
- [pkg/github/repositories.go](#pkg-github-repositories-go)
- [pkg/github/repositories_test.go](#pkg-github-repositories_test-go)
- [pkg/github/repository_resource.go](#pkg-github-repository_resource-go)
- [pkg/github/repository_resource_test.go](#pkg-github-repository_resource_test-go)
- [pkg/github/resources.go](#pkg-github-resources-go)
- [pkg/github/search.go](#pkg-github-search-go)
- [pkg/github/search_test.go](#pkg-github-search_test-go)
- [pkg/github/server.go](#pkg-github-server-go)
- [pkg/github/server_test.go](#pkg-github-server_test-go)
- [pkg/github/tools.go](#pkg-github-tools-go)
- [pkg/log/io.go](#pkg-log-io-go)
- [pkg/log/io_test.go](#pkg-log-io_test-go)
- [pkg/toolsets/toolsets.go](#pkg-toolsets-toolsets-go)
- [pkg/toolsets/toolsets_test.go](#pkg-toolsets-toolsets_test-go)
- [pkg/translations/translations.go](#pkg-translations-translations-go)
- [script/get-me](#script-get-me)
- [script/licenses](#script-licenses)
- [script/licenses-check](#script-licenses-check)
- [script/prettyprint-log](#script-prettyprint-log)
- [third-party/github.com/fsnotify/fsnotify/LICENSE](#third-party-github-com-fsnotify-fsnotify-LICENSE)
- [third-party/github.com/github/github-mcp-server/LICENSE](#third-party-github-com-github-github-mcp-server-LICENSE)
- [third-party/github.com/go-viper/mapstructure/v2/LICENSE](#third-party-github-com-go-viper-mapstructure-v2-LICENSE)
- [third-party/github.com/google/go-github/v69/github/LICENSE](#third-party-github-com-google-go-github-v69-github-LICENSE)
- [third-party/github.com/google/go-querystring/query/LICENSE](#third-party-github-com-google-go-querystring-query-LICENSE)
- [third-party/github.com/google/uuid/LICENSE](#third-party-github-com-google-uuid-LICENSE)
- [third-party/github.com/inconshreveable/mousetrap/LICENSE](#third-party-github-com-inconshreveable-mousetrap-LICENSE)
- [third-party/github.com/mark3labs/mcp-go/LICENSE](#third-party-github-com-mark3labs-mcp-go-LICENSE)
- [third-party/github.com/pelletier/go-toml/v2/LICENSE](#third-party-github-com-pelletier-go-toml-v2-LICENSE)
- [third-party/github.com/sagikazarmark/locafero/LICENSE](#third-party-github-com-sagikazarmark-locafero-LICENSE)
- [third-party/github.com/sirupsen/logrus/LICENSE](#third-party-github-com-sirupsen-logrus-LICENSE)
- [third-party/github.com/sourcegraph/conc/LICENSE](#third-party-github-com-sourcegraph-conc-LICENSE)
- [third-party/github.com/spf13/afero/LICENSE.txt](#third-party-github-com-spf13-afero-LICENSE-txt)
- [third-party/github.com/spf13/cast/LICENSE](#third-party-github-com-spf13-cast-LICENSE)
- [third-party/github.com/spf13/cobra/LICENSE.txt](#third-party-github-com-spf13-cobra-LICENSE-txt)
- [third-party/github.com/spf13/pflag/LICENSE](#third-party-github-com-spf13-pflag-LICENSE)
- [third-party/github.com/spf13/viper/LICENSE](#third-party-github-com-spf13-viper-LICENSE)
- [third-party/github.com/subosito/gotenv/LICENSE](#third-party-github-com-subosito-gotenv-LICENSE)
- [third-party/github.com/yosida95/uritemplate/v3/LICENSE](#third-party-github-com-yosida95-uritemplate-v3-LICENSE)
- [third-party/golang.org/x/sys/unix/LICENSE](#third-party-golang-org-x-sys-unix-LICENSE)
- [third-party/golang.org/x/sys/windows/LICENSE](#third-party-golang-org-x-sys-windows-LICENSE)
- [third-party/golang.org/x/text/LICENSE](#third-party-golang-org-x-text-LICENSE)
- [third-party/gopkg.in/yaml.v3/LICENSE](#third-party-gopkg-in-yaml-v3-LICENSE)
- [third-party/gopkg.in/yaml.v3/NOTICE](#third-party-gopkg-in-yaml-v3-NOTICE)

---

## `.golangci.yml`

```yaml
run:
  timeout: 5m
  tests: true
  concurrency: 4

linters:
  enable:
    - govet
    - errcheck
    - staticcheck
    - gofmt
    - goimports
    - revive
    - ineffassign
    - typecheck
    - unused
    - gosimple
    - misspell
    - nakedret
    - bodyclose
    - gocritic
    - makezero
    - gosec

output:
  formats: colored-line-number
  print-issued-lines: true
  print-linter-name: true
```

---

## `.goreleaser.yaml`

```yaml
version: 2
project_name: github-mcp-server
before:
  hooks:
    - go mod tidy
    - go generate ./...

builds:
  - env:
      - CGO_ENABLED=0
    ldflags:
      - -s -w -X main.version={{.Version}} -X main.commit={{.Commit}} -X main.date={{.Date}}
    goos:
      - linux
      - windows
      - darwin
    main: ./cmd/github-mcp-server

archives:
  - formats: tar.gz
    # this name template makes the OS and Arch compatible with the results of `uname`.
    name_template: >-
      {{ .ProjectName }}_
      {{- title .Os }}_
      {{- if eq .Arch "amd64" }}x86_64
      {{- else if eq .Arch "386" }}i386
      {{- else }}{{ .Arch }}{{ end }}
      {{- if .Arm }}v{{ .Arm }}{{ end }}
    # use zip for windows archives
    format_overrides:
      - goos: windows
        formats: zip

changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"

release:
  draft: true
  prerelease: auto
  name_template: "GitHub MCP Server {{.Version}}"
```

---

## `Dockerfile`

```
ARG VERSION="dev"

FROM golang:1.23.7 AS build
# allow this step access to build arg
ARG VERSION
# Set the working directory
WORKDIR /build

RUN go env -w GOMODCACHE=/root/.cache/go-build

# Install dependencies
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build go mod download

COPY . ./
# Build the server
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION} -X main.commit=$(git rev-parse HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o github-mcp-server cmd/github-mcp-server/main.go

# Make a stage to run the app
FROM gcr.io/distroless/base-debian12
# Set the working directory
WORKDIR /server
# Copy the binary from the build stage
COPY --from=build /build/github-mcp-server .
# Command to run the server
CMD ["./github-mcp-server", "stdio"]
```

---

## `LICENSE`

```
MIT License

Copyright (c) 2025 GitHub

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## `cmd/github-mcp-server/main.go`

```go
package main

import (
	"context"
	"fmt"
	"io"
	stdlog "log"
	"os"
	"os/signal"
	"syscall"

	"github.com/github/github-mcp-server/pkg/github"
	iolog "github.com/github/github-mcp-server/pkg/log"
	"github.com/github/github-mcp-server/pkg/translations"
	gogithub "github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var version = "version"
var commit = "commit"
var date = "date"

var (
	rootCmd = &cobra.Command{
		Use:     "server",
		Short:   "GitHub MCP Server",
		Long:    `A GitHub MCP server that handles various tools and resources.`,
		Version: fmt.Sprintf("%s (%s) %s", version, commit, date),
	}

	stdioCmd = &cobra.Command{
		Use:   "stdio",
		Short: "Start stdio server",
		Long:  `Start a server that communicates via standard input/output streams using JSON-RPC messages.`,
		Run: func(_ *cobra.Command, _ []string) {
			logFile := viper.GetString("log-file")
			readOnly := viper.GetBool("read-only")
			exportTranslations := viper.GetBool("export-translations")
			logger, err := initLogger(logFile)
			if err != nil {
				stdlog.Fatal("Failed to initialize logger:", err)
			}

			enabledToolsets := viper.GetStringSlice("toolsets")

			logCommands := viper.GetBool("enable-command-logging")
			cfg := runConfig{
				readOnly:           readOnly,
				logger:             logger,
				logCommands:        logCommands,
				exportTranslations: exportTranslations,
				enabledToolsets:    enabledToolsets,
			}
			if err := runStdioServer(cfg); err != nil {
				stdlog.Fatal("failed to run stdio server:", err)
			}
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	// Add global flags that will be shared by all commands
	rootCmd.PersistentFlags().StringSlice("toolsets", github.DefaultTools, "An optional comma separated list of groups of tools to allow, defaults to enabling all")
	rootCmd.PersistentFlags().Bool("dynamic-toolsets", false, "Enable dynamic toolsets")
	rootCmd.PersistentFlags().Bool("read-only", false, "Restrict the server to read-only operations")
	rootCmd.PersistentFlags().String("log-file", "", "Path to log file")
	rootCmd.PersistentFlags().Bool("enable-command-logging", false, "When enabled, the server will log all command requests and responses to the log file")
	rootCmd.PersistentFlags().Bool("export-translations", false, "Save translations to a JSON file")
	rootCmd.PersistentFlags().String("gh-host", "", "Specify the GitHub hostname (for GitHub Enterprise etc.)")

	// Bind flag to viper
	_ = viper.BindPFlag("toolsets", rootCmd.PersistentFlags().Lookup("toolsets"))
	_ = viper.BindPFlag("dynamic_toolsets", rootCmd.PersistentFlags().Lookup("dynamic-toolsets"))
	_ = viper.BindPFlag("read-only", rootCmd.PersistentFlags().Lookup("read-only"))
	_ = viper.BindPFlag("log-file", rootCmd.PersistentFlags().Lookup("log-file"))
	_ = viper.BindPFlag("enable-command-logging", rootCmd.PersistentFlags().Lookup("enable-command-logging"))
	_ = viper.BindPFlag("export-translations", rootCmd.PersistentFlags().Lookup("export-translations"))
	_ = viper.BindPFlag("host", rootCmd.PersistentFlags().Lookup("gh-host"))

	// Add subcommands
	rootCmd.AddCommand(stdioCmd)
}

func initConfig() {
	// Initialize Viper configuration
	viper.SetEnvPrefix("github")
	viper.AutomaticEnv()
}

func initLogger(outPath string) (*log.Logger, error) {
	if outPath == "" {
		return log.New(), nil
	}

	file, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := log.New()
	logger.SetLevel(log.DebugLevel)
	logger.SetOutput(file)

	return logger, nil
}

type runConfig struct {
	readOnly           bool
	logger             *log.Logger
	logCommands        bool
	exportTranslations bool
	enabledToolsets    []string
}

func runStdioServer(cfg runConfig) error {
	// Create app context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Create GH client
	token := viper.GetString("personal_access_token")
	if token == "" {
		cfg.logger.Fatal("GITHUB_PERSONAL_ACCESS_TOKEN not set")
	}
	ghClient := gogithub.NewClient(nil).WithAuthToken(token)
	ghClient.UserAgent = fmt.Sprintf("github-mcp-server/%s", version)

	host := viper.GetString("host")

	if host != "" {
		var err error
		ghClient, err = ghClient.WithEnterpriseURLs(host, host)
		if err != nil {
			return fmt.Errorf("failed to create GitHub client with host: %w", err)
		}
	}

	t, dumpTranslations := translations.TranslationHelper()

	beforeInit := func(_ context.Context, _ any, message *mcp.InitializeRequest) {
		ghClient.UserAgent = fmt.Sprintf("github-mcp-server/%s (%s/%s)", version, message.Params.ClientInfo.Name, message.Params.ClientInfo.Version)
	}

	getClient := func(_ context.Context) (*gogithub.Client, error) {
		return ghClient, nil // closing over client
	}

	hooks := &server.Hooks{
		OnBeforeInitialize: []server.OnBeforeInitializeFunc{beforeInit},
	}
	// Create server
	ghServer := github.NewServer(version, server.WithHooks(hooks))

	enabled := cfg.enabledToolsets
	dynamic := viper.GetBool("dynamic_toolsets")
	if dynamic {
		// filter "all" from the enabled toolsets
		enabled = make([]string, 0, len(cfg.enabledToolsets))
		for _, toolset := range cfg.enabledToolsets {
			if toolset != "all" {
				enabled = append(enabled, toolset)
			}
		}
	}

	// Create default toolsets
	toolsets, err := github.InitToolsets(enabled, cfg.readOnly, getClient, t)
	context := github.InitContextToolset(getClient, t)

	if err != nil {
		stdlog.Fatal("Failed to initialize toolsets:", err)
	}

	// Register resources with the server
	github.RegisterResources(ghServer, getClient, t)
	// Register the tools with the server
	toolsets.RegisterTools(ghServer)
	context.RegisterTools(ghServer)

	if dynamic {
		dynamic := github.InitDynamicToolset(ghServer, toolsets, t)
		dynamic.RegisterTools(ghServer)
	}

	stdioServer := server.NewStdioServer(ghServer)

	stdLogger := stdlog.New(cfg.logger.Writer(), "stdioserver", 0)
	stdioServer.SetErrorLogger(stdLogger)

	if cfg.exportTranslations {
		// Once server is initialized, all translations are loaded
		dumpTranslations()
	}

	// Start listening for messages
	errC := make(chan error, 1)
	go func() {
		in, out := io.Reader(os.Stdin), io.Writer(os.Stdout)

		if cfg.logCommands {
			loggedIO := iolog.NewIOLogger(in, out, cfg.logger)
			in, out = loggedIO, loggedIO
		}

		errC <- stdioServer.Listen(ctx, in, out)
	}()

	// Output github-mcp-server string
	_, _ = fmt.Fprintf(os.Stderr, "GitHub MCP Server running on stdio\n")

	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		cfg.logger.Infof("shutting down server...")
	case err := <-errC:
		if err != nil {
			return fmt.Errorf("error running server: %w", err)
		}
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
```

---

## `cmd/mcpcurl/main.go`

```go
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type (
	// SchemaResponse represents the top-level response containing tools
	SchemaResponse struct {
		Result  Result `json:"result"`
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
	}

	// Result contains the list of available tools
	Result struct {
		Tools []Tool `json:"tools"`
	}

	// Tool represents a single command with its schema
	Tool struct {
		Name        string      `json:"name"`
		Description string      `json:"description"`
		InputSchema InputSchema `json:"inputSchema"`
	}

	// InputSchema defines the structure of a tool's input parameters
	InputSchema struct {
		Type                 string              `json:"type"`
		Properties           map[string]Property `json:"properties"`
		Required             []string            `json:"required"`
		AdditionalProperties bool                `json:"additionalProperties"`
		Schema               string              `json:"$schema"`
	}

	// Property defines a single parameter's type and constraints
	Property struct {
		Type        string        `json:"type"`
		Description string        `json:"description"`
		Enum        []string      `json:"enum,omitempty"`
		Minimum     *float64      `json:"minimum,omitempty"`
		Maximum     *float64      `json:"maximum,omitempty"`
		Items       *PropertyItem `json:"items,omitempty"`
	}

	// PropertyItem defines the type of items in an array property
	PropertyItem struct {
		Type                 string              `json:"type"`
		Properties           map[string]Property `json:"properties,omitempty"`
		Required             []string            `json:"required,omitempty"`
		AdditionalProperties bool                `json:"additionalProperties,omitempty"`
	}

	// JSONRPCRequest represents a JSON-RPC 2.0 request
	JSONRPCRequest struct {
		JSONRPC string        `json:"jsonrpc"`
		ID      int           `json:"id"`
		Method  string        `json:"method"`
		Params  RequestParams `json:"params"`
	}

	// RequestParams contains the tool name and arguments
	RequestParams struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	// Define structure to match the response format
	Content struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}

	ResponseResult struct {
		Content []Content `json:"content"`
	}

	Response struct {
		Result  ResponseResult `json:"result"`
		JSONRPC string         `json:"jsonrpc"`
		ID      int            `json:"id"`
	}
)

var (
	// Create root command
	rootCmd = &cobra.Command{
		Use:   "mcpcurl",
		Short: "CLI tool with dynamically generated commands",
		Long:  "A CLI tool for interacting with MCP API based on dynamically loaded schemas",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// Skip validation for help and completion commands
			if cmd.Name() == "help" || cmd.Name() == "completion" {
				return nil
			}

			// Check if the required global flag is provided
			serverCmd, _ := cmd.Flags().GetString("stdio-server-cmd")
			if serverCmd == "" {
				return fmt.Errorf("--stdio-server-cmd is required")
			}
			return nil
		},
	}

	// Add schema command
	schemaCmd = &cobra.Command{
		Use:   "schema",
		Short: "Fetch schema from MCP server",
		Long:  "Fetches the tools schema from the MCP server specified by --stdio-server-cmd",
		RunE: func(cmd *cobra.Command, _ []string) error {
			serverCmd, _ := cmd.Flags().GetString("stdio-server-cmd")
			if serverCmd == "" {
				return fmt.Errorf("--stdio-server-cmd is required")
			}

			// Build the JSON-RPC request for tools/list
			jsonRequest, err := buildJSONRPCRequest("tools/list", "", nil)
			if err != nil {
				return fmt.Errorf("failed to build JSON-RPC request: %w", err)
			}

			// Execute the server command and pass the JSON-RPC request
			response, err := executeServerCommand(serverCmd, jsonRequest)
			if err != nil {
				return fmt.Errorf("error executing server command: %w", err)
			}

			// Output the response
			fmt.Println(response)
			return nil
		},
	}

	// Create the tools command
	toolsCmd = &cobra.Command{
		Use:   "tools",
		Short: "Access available tools",
		Long:  "Contains all dynamically generated tool commands from the schema",
	}
)

func main() {
	rootCmd.AddCommand(schemaCmd)

	// Add global flag for stdio server command
	rootCmd.PersistentFlags().String("stdio-server-cmd", "", "Shell command to invoke MCP server via stdio (required)")
	_ = rootCmd.MarkPersistentFlagRequired("stdio-server-cmd")

	// Add global flag for pretty printing
	rootCmd.PersistentFlags().Bool("pretty", true, "Pretty print MCP response (only for JSON or JSONL responses)")

	// Add the tools command to the root command
	rootCmd.AddCommand(toolsCmd)

	// Execute the root command once to parse flags
	_ = rootCmd.ParseFlags(os.Args[1:])

	// Get pretty flag
	prettyPrint, err := rootCmd.Flags().GetBool("pretty")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error getting pretty flag: %v\n", err)
		os.Exit(1)
	}
	// Get server command
	serverCmd, err := rootCmd.Flags().GetString("stdio-server-cmd")
	if err == nil && serverCmd != "" {
		// Fetch schema from server
		jsonRequest, err := buildJSONRPCRequest("tools/list", "", nil)
		if err == nil {
			response, err := executeServerCommand(serverCmd, jsonRequest)
			if err == nil {
				// Parse the schema response
				var schemaResp SchemaResponse
				if err := json.Unmarshal([]byte(response), &schemaResp); err == nil {
					// Add all the generated commands as subcommands of tools
					for _, tool := range schemaResp.Result.Tools {
						addCommandFromTool(toolsCmd, &tool, prettyPrint)
					}
				}
			}
		}
	}

	// Execute
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error executing command: %v\n", err)
		os.Exit(1)
	}
}

// addCommandFromTool creates a cobra command from a tool schema
func addCommandFromTool(toolsCmd *cobra.Command, tool *Tool, prettyPrint bool) {
	// Create command from tool
	cmd := &cobra.Command{
		Use:   tool.Name,
		Short: tool.Description,
		Run: func(cmd *cobra.Command, _ []string) {
			// Build a map of arguments from flags
			arguments, err := buildArgumentsMap(cmd, tool)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to build arguments map: %v\n", err)
				return
			}

			jsonData, err := buildJSONRPCRequest("tools/call", tool.Name, arguments)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to build JSONRPC request: %v\n", err)
				return
			}

			// Execute the server command
			serverCmd, err := cmd.Flags().GetString("stdio-server-cmd")
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to get stdio-server-cmd: %v\n", err)
				return
			}
			response, err := executeServerCommand(serverCmd, jsonData)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "error executing server command: %v\n", err)
				return
			}
			if err := printResponse(response, prettyPrint); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "error printing response: %v\n", err)
				return
			}
		},
	}

	// Initialize viper for this command
	viperInit := func() {
		viper.Reset()
		viper.AutomaticEnv()
		viper.SetEnvPrefix(strings.ToUpper(tool.Name))
		viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	}

	// We'll call the init function directly instead of with cobra.OnInitialize
	// to avoid conflicts between commands
	viperInit()

	// Add flags based on schema properties
	for name, prop := range tool.InputSchema.Properties {
		isRequired := slices.Contains(tool.InputSchema.Required, name)

		// Enhance description to indicate if parameter is optional
		description := prop.Description
		if !isRequired {
			description += " (optional)"
		}

		switch prop.Type {
		case "string":
			cmd.Flags().String(name, "", description)
			if len(prop.Enum) > 0 {
				// Add validation in PreRun for enum values
				cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
					for flagName, property := range tool.InputSchema.Properties {
						if len(property.Enum) > 0 {
							value, _ := cmd.Flags().GetString(flagName)
							if value != "" && !slices.Contains(property.Enum, value) {
								return fmt.Errorf("%s must be one of: %s", flagName, strings.Join(property.Enum, ", "))
							}
						}
					}
					return nil
				}
			}
		case "number":
			cmd.Flags().Float64(name, 0, description)
		case "boolean":
			cmd.Flags().Bool(name, false, description)
		case "array":
			if prop.Items != nil {
				if prop.Items.Type == "string" {
					cmd.Flags().StringSlice(name, []string{}, description)
				} else if prop.Items.Type == "object" {
					// For complex objects in arrays, we'll use a JSON string that users can provide
					cmd.Flags().String(name+"-json", "", description+" (provide as JSON array)")
				}
			}
		}

		if isRequired {
			_ = cmd.MarkFlagRequired(name)
		}

		// Bind flag to viper
		_ = viper.BindPFlag(name, cmd.Flags().Lookup(name))
	}

	// Add command to root
	toolsCmd.AddCommand(cmd)
}

// buildArgumentsMap extracts flag values into a map of arguments
func buildArgumentsMap(cmd *cobra.Command, tool *Tool) (map[string]interface{}, error) {
	arguments := make(map[string]interface{})

	for name, prop := range tool.InputSchema.Properties {
		switch prop.Type {
		case "string":
			if value, _ := cmd.Flags().GetString(name); value != "" {
				arguments[name] = value
			}
		case "number":
			if value, _ := cmd.Flags().GetFloat64(name); value != 0 {
				arguments[name] = value
			}
		case "boolean":
			// For boolean, we need to check if it was explicitly set
			if cmd.Flags().Changed(name) {
				value, _ := cmd.Flags().GetBool(name)
				arguments[name] = value
			}
		case "array":
			if prop.Items != nil {
				if prop.Items.Type == "string" {
					if values, _ := cmd.Flags().GetStringSlice(name); len(values) > 0 {
						arguments[name] = values
					}
				} else if prop.Items.Type == "object" {
					if jsonStr, _ := cmd.Flags().GetString(name + "-json"); jsonStr != "" {
						var jsonArray []interface{}
						if err := json.Unmarshal([]byte(jsonStr), &jsonArray); err != nil {
							return nil, fmt.Errorf("error parsing JSON for %s: %w", name, err)
						}
						arguments[name] = jsonArray
					}
				}
			}
		}
	}

	return arguments, nil
}

// buildJSONRPCRequest creates a JSON-RPC request with the given tool name and arguments
func buildJSONRPCRequest(method, toolName string, arguments map[string]interface{}) (string, error) {
	id, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return "", fmt.Errorf("failed to generate random ID: %w", err)
	}
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      int(id.Int64()), // Random ID between 0 and 9999
		Method:  method,
		Params: RequestParams{
			Name:      toolName,
			Arguments: arguments,
		},
	}
	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON request: %w", err)
	}
	return string(jsonData), nil
}

// executeServerCommand runs the specified command, sends the JSON request to stdin,
// and returns the response from stdout
func executeServerCommand(cmdStr, jsonRequest string) (string, error) {
	// Split the command string into command and arguments
	cmdParts := strings.Fields(cmdStr)
	if len(cmdParts) == 0 {
		return "", fmt.Errorf("empty command")
	}

	cmd := exec.Command(cmdParts[0], cmdParts[1:]...) //nolint:gosec //mcpcurl is a test command that needs to execute arbitrary shell commands

	// Setup stdin pipe
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	// Setup stdout and stderr pipes
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start the command
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}

	// Write the JSON request to stdin
	if _, err := io.WriteString(stdin, jsonRequest+"\n"); err != nil {
		return "", fmt.Errorf("failed to write to stdin: %w", err)
	}
	_ = stdin.Close()

	// Wait for the command to complete
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("command failed: %w, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

func printResponse(response string, prettyPrint bool) error {
	if !prettyPrint {
		fmt.Println(response)
		return nil
	}

	// Parse the JSON response
	var resp Response
	if err := json.Unmarshal([]byte(response), &resp); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Extract text from content items of type "text"
	for _, content := range resp.Result.Content {
		if content.Type == "text" {
			var textContentObj map[string]interface{}
			err := json.Unmarshal([]byte(content.Text), &textContentObj)

			if err == nil {
				prettyText, err := json.MarshalIndent(textContentObj, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to pretty print text content: %w", err)
				}
				fmt.Println(string(prettyText))
				continue
			}

			// Fallback parsing as JSONL
			var textContentList []map[string]interface{}
			if err := json.Unmarshal([]byte(content.Text), &textContentList); err != nil {
				return fmt.Errorf("failed to parse text content as a list: %w", err)
			}
			prettyText, err := json.MarshalIndent(textContentList, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to pretty print array content: %w", err)
			}
			fmt.Println(string(prettyText))
		}
	}

	// If no text content found, print the original response
	if len(resp.Result.Content) == 0 {
		fmt.Println(response)
	}

	return nil
}
```

---

## `combine.py`

```python
#!/usr/bin/env python3
import os
import fnmatch
import argparse
import subprocess
from typing import List, Optional, Dict, Set

# 文件扩展名到 Markdown 语言标识符的映射
EXTENSION_MAP = {
    '.py': 'python',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.jsx': 'jsx',
    '.tsx': 'tsx',
    '.java': 'java',
    '.c': 'c',
    '.cpp': 'cpp',
    '.cs': 'csharp',
    '.go': 'go',
    '.rb': 'ruby',
    '.php': 'php',
    '.html': 'html',
    '.css': 'css',
    '.scss': 'scss',
    '.sass': 'sass',
    '.less': 'less',
    '.sql': 'sql',
    '.sh': 'bash',
    '.bash': 'bash',
    '.zsh': 'bash',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.json': 'json',
    '.xml': 'xml',
    '.kt': 'kotlin',
    '.swift': 'swift',
    '.rs': 'rust',
    '.dart': 'dart',
    '.lua': 'lua',
    '.r': 'r',
    '.scala': 'scala',
    '.pl': 'perl',
    '.h': 'cpp',
    '.hpp': 'cpp',
    '.conf': 'ini',
    '.ini': 'ini',
    '.toml': 'toml',
    '.md': 'markdown',
    '.vue': 'vue',
    '.svelte': 'svelte',
}

# 默认排除的模式
DEFAULT_EXCLUDES = [
    '*.md',
    '*.git*',
    '*.log',
    '*.jpg', '*.jpeg', '*.png', '*.gif', '*.webp', '*.svg', '*.bmp', '*.ico',  # 图片文件
    '*.pdf', '*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx',  # 文档文件
    '*.zip', '*.tar', '*.gz', '*.rar', '*.7z',  # 压缩文件
    '*.mp3', '*.mp4', '*.avi', '*.mov', '*.wav', '*.ogg',  # 媒体文件
    '*.ttf', '*.otf', '*.woff', '*.woff2', '*.eot',  # 字体文件
    '*.bin', '*.dat', '*.so', '*.dll', '*.exe',  # 二进制文件
    'node_modules/*',
    'venv/*',
    '.venv/*',
    '__pycache__/*',
    'dist/*',
    'build/*',
    '.next/*',
    'out/*',
    '.vscode/*',
    '.idea/*',
    "pnpm-lock.yaml",
    "tailwindcss-v4-reference.css",
]

def is_git_repo() -> bool:
    """检查当前目录是否是 Git 仓库"""
    try:
        subprocess.run(
            ['git', 'rev-parse', '--is-inside-work-tree'],
            capture_output=True, check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def get_tracked_files() -> Optional[List[str]]:
    """获取 Git 跟踪的所有文件列表"""
    try:
        result = subprocess.run(
            ['git', 'ls-files', '--cached', '--exclude-standard'],
            capture_output=True, text=True, check=True, encoding='utf-8'
        )
        return result.stdout.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def should_exclude_dir(dirpath: str, dirname: str, exclude_patterns: List[str]) -> bool:
    """检查目录是否应该被排除"""
    full_path = os.path.join(dirpath, dirname)
    
    # 排除隐藏目录（以点开头）
    if dirname.startswith('.'):
        return True
        
    for pattern in exclude_patterns:
        # 匹配目录名本身
        if fnmatch.fnmatch(dirname, pattern.rstrip('/*')):
            return True
            
        # 匹配完整路径
        if fnmatch.fnmatch(full_path, pattern):
            return True
            
        # 匹配目录通配符 (如 node_modules/*)
        if pattern.endswith('/*') and fnmatch.fnmatch(full_path, pattern[:-2]):
            return True
    
    return False

def get_files_by_walking(root_dir: str, exclude_patterns: List[str]) -> List[str]:
    """通过遍历文件系统获取文件列表，支持排除模式"""
    files_list = []
    
    for dirpath, dirnames, filenames in os.walk(root_dir, topdown=True):
        # 过滤排除的目录（修复排除逻辑）
        dirnames[:] = [d for d in dirnames if not should_exclude_dir(dirpath, d, exclude_patterns)]
        
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(file_path, root_dir)
            
            # 检查文件是否应被排除
            if not any(fnmatch.fnmatch(rel_path, pattern) for pattern in exclude_patterns):
                files_list.append(rel_path)
    
    return files_list

def get_language_identifier(filename: str) -> str:
    """根据文件扩展名获取 Markdown 语言标识符"""
    _, ext = os.path.splitext(filename)
    return EXTENSION_MAP.get(ext.lower(), '')  # 如果找不到映射，则返回空字符串

def should_exclude(filename: str, exclude_patterns: List[str]) -> bool:
    """检查文件是否匹配任何排除模式"""
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False

def is_binary_file(filepath: str) -> bool:
    """检查文件是否是二进制文件"""
    # 检查文件扩展名
    _, ext = os.path.splitext(filepath)
    if ext.lower() in {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', 
                      '.exe', '.dll', '.so', '.pyc', '.zip', '.tar', '.gz'}:
        return True
        
    # 尝试读取文件开头的字节来检测二进制内容
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk  # 如果包含空字节，通常是二进制文件
    except Exception:
        # 如果无法打开文件，出于安全考虑将其视为二进制
        return True

def combine_code_to_markdown(
    output_filename: str = "project_code.md", 
    exclude_list: Optional[List[str]] = None,
    use_git: bool = True,
    root_dir: str = ".",
    verbose: bool = False,
    max_lines: Optional[int] = None
) -> None:
    """将符合条件的文件合并到 Markdown 文件中"""
    if exclude_list is None:
        exclude_list = DEFAULT_EXCLUDES.copy()
    
    # 始终排除输出文件
    if output_filename not in exclude_list:
        exclude_list.append(output_filename)
        exclude_list.append(f"*/{output_filename}")  # 防止在子目录中有同名文件
    
    if verbose:
        print(f"排除模式: {exclude_list}")
    
    if use_git and is_git_repo():
        if verbose:
            print("使用 Git 获取文件列表...")
        files = get_tracked_files()
        if not files:
            print("未找到 Git 跟踪的文件或无法执行 Git 命令。")
            return
    else:
        if verbose and use_git:
            print("未找到 Git 仓库，使用文件系统遍历...")
        files = get_files_by_walking(root_dir, exclude_list)
    
    # 对文件列表进行进一步过滤，排除二进制文件
    filtered_files = []
    skipped_binaries = []
    
    for filename in files:
        full_path = os.path.join(root_dir, filename)
        
        if not os.path.exists(full_path) or not os.path.isfile(full_path):
            if verbose:
                print(f"跳过不存在或非文件: {filename}")
            continue
            
        if is_binary_file(full_path):
            skipped_binaries.append(filename)
            if verbose:
                print(f"跳过二进制文件: {filename}")
            continue
            
        if not any(fnmatch.fnmatch(filename, pattern) for pattern in exclude_list):
            filtered_files.append(filename)
        elif verbose:
            print(f"排除: {filename}")
    
    if not filtered_files:
        print("过滤后没有文件可以处理。")
        return
    
    if verbose and skipped_binaries:
        print(f"跳过了 {len(skipped_binaries)} 个二进制文件。")
    
    # 排序文件列表以确保一致性
    filtered_files.sort()
    
    if verbose:
        print(f"处理 {len(filtered_files)} 个文件，写入到 {output_filename}...")
    
    project_name = os.path.basename(os.path.abspath(root_dir))
    
    try:
        with open(output_filename, 'w', encoding='utf-8') as outfile:
            # 添加标题和简介
            outfile.write(f"# {project_name} 代码库\n\n")
            outfile.write("*通过 combine_code.py 自动生成*\n\n")
            outfile.write("## 目录\n\n")
            
            # 生成目录
            for filename in filtered_files:
                outfile.write(f"- [{filename}](#{filename.replace('/', '-').replace('.', '-')})\n")
            
            outfile.write("\n---\n\n")
            
            # 写入文件内容
            for filename in filtered_files:
                if verbose:
                    print(f"处理: {filename}")
                
                file_path = os.path.join(root_dir, filename)
                
                # 为每个文件创建锚点兼容的标题
                outfile.write(f"## `{filename}`\n\n")
                
                # 获取语言标识符并写入代码块
                lang = get_language_identifier(filename)
                outfile.write(f"```{lang}\n")
                
                try:
                    # 逐行读取文件以处理大文件
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as infile:
                        if max_lines is not None:
                            # 如果设置了最大行数限制
                            for i, line in enumerate(infile):
                                if i >= max_lines:
                                    outfile.write(f"\n... (已截断，显示了 {max_lines} 行中的前 {max_lines} 行) ...\n")
                                    break
                                outfile.write(line)
                        else:
                            # 无行数限制，直接逐行复制
                            for line in infile:
                                outfile.write(line)
                except Exception as e:
                    error_msg = f"\n[读取文件时出错: {e}]\n"
                    outfile.write(error_msg)
                    if verbose:
                        print(f"错误: 无法读取文件 {filename}: {e}")
                
                outfile.write("```\n\n")
                outfile.write("---\n\n")
        
        print(f"✅ 成功将代码合并到 {output_filename}")
        
    except IOError as e:
        print(f"❌ 写入输出文件 {output_filename} 时出错: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="将代码文件合并到单个 Markdown 文件中，支持 Git 跟踪的文件或文件系统遍历。",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "-o", "--output",
        default="project_code.md",
        help="输出的 Markdown 文件名"
    )
    
    parser.add_argument(
        "-e", "--exclude",
        action='append',
        help="要排除的 glob 模式（可多次使用）"
    )
    
    parser.add_argument(
        "--no-git",
        action='store_true',
        help="不使用 Git，始终使用文件系统遍历"
    )
    
    parser.add_argument(
        "-d", "--directory",
        default=".",
        help="要处理的项目根目录（当不使用 Git 时）"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action='store_true',
        help="显示详细处理信息"
    )
    
    parser.add_argument(
        "--max-lines",
        type=int,
        help="每个文件的最大行数（超过将被截断）"
    )
    
    args = parser.parse_args()
    
    # 如果用户提供了排除列表，使用它，否则使用默认列表
    exclusions = args.exclude if args.exclude else DEFAULT_EXCLUDES.copy()
    
    combine_code_to_markdown(
        output_filename=args.output,
        exclude_list=exclusions,
        use_git=not args.no_git,
        root_dir=args.directory,
        verbose=args.verbose,
        max_lines=args.max_lines
    )```

---

## `conformance/conformance_test.go`

```go
//go:build conformance

package conformance_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
)

type maintainer string

const (
	anthropic maintainer = "anthropic"
	github    maintainer = "github"
)

type testLogWriter struct {
	t *testing.T
}

func (w testLogWriter) Write(p []byte) (n int, err error) {
	w.t.Log(string(p))
	return len(p), nil
}

func start(t *testing.T, m maintainer) server {
	var image string
	if m == github {
		image = "github/github-mcp-server"
	} else {
		image = "mcp/github"
	}

	ctx := context.Background()
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)

	containerCfg := &container.Config{
		OpenStdin:    true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Env: []string{
			fmt.Sprintf("GITHUB_PERSONAL_ACCESS_TOKEN=%s", os.Getenv("GITHUB_PERSONAL_ACCESS_TOKEN")),
		},
		Image: image,
	}

	resp, err := dockerClient.ContainerCreate(
		ctx,
		containerCfg,
		&container.HostConfig{},
		&network.NetworkingConfig{},
		nil,
		"")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, dockerClient.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true}))
	})

	hijackedResponse, err := dockerClient.ContainerAttach(ctx, resp.ID, container.AttachOptions{
		Stream: true,
		Stdin:  true,
		Stdout: true,
		Stderr: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { hijackedResponse.Close() })

	require.NoError(t, dockerClient.ContainerStart(ctx, resp.ID, container.StartOptions{}))

	serverStart := make(chan serverStartResult)
	go func() {
		prOut, pwOut := io.Pipe()
		prErr, pwErr := io.Pipe()

		go func() {
			// Ignore error, we should be done?
			// TODO: maybe check for use of closed network connection specifically
			_, _ = stdcopy.StdCopy(pwOut, pwErr, hijackedResponse.Reader)
			pwOut.Close()
			pwErr.Close()
		}()

		bufferedStderr := bufio.NewReader(prErr)
		line, err := bufferedStderr.ReadString('\n')
		if err != nil {
			serverStart <- serverStartResult{err: err}
		}

		if strings.TrimSpace(line) != "GitHub MCP Server running on stdio" {
			serverStart <- serverStartResult{
				err: fmt.Errorf("unexpected server output: %s", line),
			}
			return
		}

		serverStart <- serverStartResult{
			server: server{
				m:      m,
				log:    testLogWriter{t},
				stdin:  hijackedResponse.Conn,
				stdout: bufio.NewReader(prOut),
			},
		}
	}()

	t.Logf("waiting for %s server to start...", m)
	serveResult := <-serverStart
	require.NoError(t, serveResult.err, "expected the server to start successfully")

	return serveResult.server
}

func TestCapabilities(t *testing.T) {
	anthropicServer := start(t, anthropic)
	githubServer := start(t, github)

	req := initializeRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: initializeParams{
			ProtocolVersion: "2025-03-26",
			Capabilities:    clientCapabilities{},
			ClientInfo: clientInfo{
				Name:    "ConformanceTest",
				Version: "0.0.1",
			},
		},
	}

	require.NoError(t, anthropicServer.send(req))

	var anthropicInitializeResponse initializeResponse
	require.NoError(t, anthropicServer.receive(&anthropicInitializeResponse))

	require.NoError(t, githubServer.send(req))

	var ghInitializeResponse initializeResponse
	require.NoError(t, githubServer.receive(&ghInitializeResponse))

	// Any capabilities in the anthropic response should be present in the github response
	// (though the github response may have additional capabilities)
	if diff := diffNonNilFields(anthropicInitializeResponse.Result.Capabilities, ghInitializeResponse.Result.Capabilities, ""); diff != "" {
		t.Errorf("capabilities mismatch:\n%s", diff)
	}
}

func diffNonNilFields(a, b interface{}, path string) string {
	var sb strings.Builder

	va := reflect.ValueOf(a)
	vb := reflect.ValueOf(b)

	if !va.IsValid() {
		return ""
	}

	if va.Kind() == reflect.Ptr {
		if va.IsNil() {
			return ""
		}
		if !vb.IsValid() || vb.IsNil() {
			sb.WriteString(path + "\n")
			return sb.String()
		}
		va = va.Elem()
		vb = vb.Elem()
	}

	if va.Kind() != reflect.Struct || vb.Kind() != reflect.Struct {
		return ""
	}

	t := va.Type()
	for i := range va.NumField() {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}

		subPath := field.Name
		if path != "" {
			subPath = fmt.Sprintf("%s.%s", path, field.Name)
		}

		fieldA := va.Field(i)
		fieldB := vb.Field(i)

		switch fieldA.Kind() {
		case reflect.Ptr:
			if fieldA.IsNil() {
				continue // not required
			}
			if fieldB.IsNil() {
				sb.WriteString(subPath + "\n")
				continue
			}
			sb.WriteString(diffNonNilFields(fieldA.Interface(), fieldB.Interface(), subPath))

		case reflect.Struct:
			sb.WriteString(diffNonNilFields(fieldA.Interface(), fieldB.Interface(), subPath))

		default:
			zero := reflect.Zero(fieldA.Type())
			if !reflect.DeepEqual(fieldA.Interface(), zero.Interface()) {
				// fieldA is non-zero; now check that fieldB matches
				if !reflect.DeepEqual(fieldA.Interface(), fieldB.Interface()) {
					sb.WriteString(subPath + "\n")
				}
			}
		}
	}

	return sb.String()
}

func TestListTools(t *testing.T) {
	anthropicServer := start(t, anthropic)
	githubServer := start(t, github)

	req := listToolsRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	require.NoError(t, anthropicServer.send(req))

	var anthropicListToolsResponse listToolsResponse
	require.NoError(t, anthropicServer.receive(&anthropicListToolsResponse))

	require.NoError(t, githubServer.send(req))

	var ghListToolsResponse listToolsResponse
	require.NoError(t, githubServer.receive(&ghListToolsResponse))

	require.NoError(t, isToolListSubset(anthropicListToolsResponse.Result, ghListToolsResponse.Result), "expected the github list tools response to be a subset of the anthropic list tools response")
}

func isToolListSubset(subset, superset listToolsResult) error {
	// Build a map from tool name to Tool from the superset
	supersetMap := make(map[string]tool)
	for _, tool := range superset.Tools {
		supersetMap[tool.Name] = tool
	}

	var err error
	for _, tool := range subset.Tools {
		sup, ok := supersetMap[tool.Name]
		if !ok {
			return fmt.Errorf("tool %q not found in superset", tool.Name)
		}

		// Intentionally ignore the description fields because there are lots of slight differences.
		// if tool.Description != sup.Description {
		// 	return fmt.Errorf("description mismatch for tool %q, got %q expected %q", tool.Name, tool.Description, sup.Description)
		// }

		// Ignore any description fields within the input schema properties for the same reason
		ignoreDescOpt := cmp.FilterPath(func(p cmp.Path) bool {
			// Look for a field named "Properties" somewhere in the path
			for _, ps := range p {
				if sf, ok := ps.(cmp.StructField); ok && sf.Name() == "Properties" {
					return true
				}
			}
			return false
		}, cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
			return k == "description"
		}))

		if diff := cmp.Diff(tool.InputSchema, sup.InputSchema, ignoreDescOpt); diff != "" {
			err = errors.Join(err, fmt.Errorf("inputSchema mismatch for tool %q:\n%s", tool.Name, diff))
		}
	}

	return err
}

type serverStartResult struct {
	server server
	err    error
}

type server struct {
	m   maintainer
	log io.Writer

	stdin  io.Writer
	stdout *bufio.Reader
}

func (s server) send(req request) error {
	b, err := req.marshal()
	if err != nil {
		return err
	}

	fmt.Fprintf(s.log, "sending %s: %s\n", s.m, string(b))

	n, err := s.stdin.Write(append(b, '\n'))
	if err != nil {
		return err
	}

	if n != len(b)+1 {
		return fmt.Errorf("wrote %d bytes, expected %d", n, len(b)+1)
	}

	return nil
}

func (s server) receive(res response) error {
	line, err := s.stdout.ReadBytes('\n')
	if err != nil {
		if err == io.EOF {
			return fmt.Errorf("EOF after reading %s", string(line))
		}
		return err
	}

	fmt.Fprintf(s.log, "received from %s: %s\n", s.m, string(line))

	return res.unmarshal(line)
}

type request interface {
	marshal() ([]byte, error)
}

type response interface {
	unmarshal([]byte) error
}

type jsonRPRCRequest[params any] struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  params `json:"params"`
}

func (r jsonRPRCRequest[any]) marshal() ([]byte, error) {
	return json.Marshal(r)
}

type jsonRPRCResponse[result any] struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Result  result `json:"result"`
}

func (r *jsonRPRCResponse[any]) unmarshal(b []byte) error {
	return json.Unmarshal(b, r)
}

type initializeRequest = jsonRPRCRequest[initializeParams]

type initializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    clientCapabilities `json:"capabilities"`
	ClientInfo      clientInfo         `json:"clientInfo"`
}

type clientCapabilities struct{} // don't actually care about any of these right now

type clientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type initializeResponse = jsonRPRCResponse[initializeResult]

type initializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    serverCapabilities `json:"capabilities"`
	ServerInfo      serverInfo         `json:"serverInfo"`
}

type serverCapabilities struct {
	Logging *struct{} `json:"logging,omitempty"`
	Prompts *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"prompts,omitempty"`
	Resources *struct {
		Subscribe   bool `json:"subscribe,omitempty"`
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"resources,omitempty"`
	Tools *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"tools,omitempty"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type listToolsRequest = jsonRPRCRequest[struct{}]

type listToolsResponse = jsonRPRCResponse[listToolsResult]

type listToolsResult struct {
	Tools []tool `json:"tools"`
}
type tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	InputSchema inputSchema `json:"inputSchema"`
}

type inputSchema struct {
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties,omitempty"`
	Required   []string       `json:"required,omitempty"`
}
```

---

## `go.mod`

```
module github.com/github/github-mcp-server

go 1.23.7

require (
	github.com/docker/docker v28.0.4+incompatible
	github.com/google/go-cmp v0.7.0
	github.com/google/go-github/v69 v69.2.0
	github.com/mark3labs/mcp-go v0.20.1
	github.com/migueleliasweb/go-github-mock v1.1.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-github/v64 v64.0.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/sagikazarmark/locafero v0.9.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.35.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.19.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk v1.35.0 // indirect
	go.opentelemetry.io/otel/trace v1.35.0 // indirect
	go.opentelemetry.io/proto/otlp v1.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gotest.tools/v3 v3.5.1 // indirect
)
```

---

## `go.sum`

```
github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 h1:UQHMgLO+TxOElx5B5HZ4hJQsoJ/PvUvKRhJHDQXO8P8=
github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1/go.mod h1:xomTg63KZ2rFqZQzSB4Vz2SUXa1BpHTVz9L5PTmPC4E=
github.com/Microsoft/go-winio v0.6.2 h1:F2VQgta7ecxGYO8k3ZZz3RS8fVIXVxONVUPlNERoyfY=
github.com/Microsoft/go-winio v0.6.2/go.mod h1:yd8OoFMLzJbo9gZq8j5qaps8bJ9aShtEA8Ipt1oGCvU=
github.com/cenkalti/backoff/v4 v4.2.1 h1:y4OZtCnogmCPw98Zjyt5a6+QwPLGkiQsYW5oUqylYbM=
github.com/cenkalti/backoff/v4 v4.2.1/go.mod h1:Y3VNntkOUPxTVeUxJ/G5vcM//AlwfmyYozVcomhLiZE=
github.com/containerd/log v0.1.0 h1:TCJt7ioM2cr/tfR8GPbGf9/VRAX8D2B4PjzCpfX540I=
github.com/containerd/log v0.1.0/go.mod h1:VRRf09a7mHDIRezVKTRCrOq78v577GXq3bSa3EhrzVo=
github.com/cpuguy83/go-md2man/v2 v2.0.6/go.mod h1:oOW0eioCTA6cOiMLiUPZOpcVxMig6NIQQ7OS05n1F4g=
github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc h1:U9qPSI2PIWSS1VwoXQT9A3Wy9MM3WgvqSxFWenqJduM=
github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/distribution/reference v0.6.0 h1:0IXCQ5g4/QMHHkarYzh5l+u8T3t73zM5QvfrDyIgxBk=
github.com/distribution/reference v0.6.0/go.mod h1:BbU0aIcezP1/5jX/8MP0YiH4SdvB5Y4f/wlDRiLyi3E=
github.com/docker/docker v28.0.4+incompatible h1:JNNkBctYKurkw6FrHfKqY0nKIDf5nrbxjVBtS+cdcok=
github.com/docker/docker v28.0.4+incompatible/go.mod h1:eEKB0N0r5NX/I1kEveEz05bcu8tLC/8azJZsviup8Sk=
github.com/docker/go-connections v0.5.0 h1:USnMq7hx7gwdVZq1L49hLXaFtUdTADjXGp+uj1Br63c=
github.com/docker/go-connections v0.5.0/go.mod h1:ov60Kzw0kKElRwhNs9UlUHAE/F9Fe6GLaXnqyDdmEXc=
github.com/docker/go-units v0.5.0 h1:69rxXcBk27SvSaaxTtLh/8llcHD8vYHT7WSdRZ/jvr4=
github.com/docker/go-units v0.5.0/go.mod h1:fgPhTUdO+D/Jk86RDLlptpiXQzgHJF7gydDDbaIK4Dk=
github.com/felixge/httpsnoop v1.0.4 h1:NFTV2Zj1bL4mc9sqWACXbQFVBBg2W3GPvqp8/ESS2Wg=
github.com/felixge/httpsnoop v1.0.4/go.mod h1:m8KPJKqk1gH5J9DgRY2ASl2lWCfGKXixSwevea8zH2U=
github.com/frankban/quicktest v1.14.6 h1:7Xjx+VpznH+oBnejlPUj8oUpdxnVs4f8XU8WnHkI4W8=
github.com/frankban/quicktest v1.14.6/go.mod h1:4ptaffx2x8+WTWXmUCuVU6aPUX1/Mz7zb5vbUoiM6w0=
github.com/fsnotify/fsnotify v1.8.0 h1:dAwr6QBTBZIkG8roQaJjGof0pp0EeF+tNV7YBP3F/8M=
github.com/fsnotify/fsnotify v1.8.0/go.mod h1:8jBTzvmWwFyi3Pb8djgCCO5IBqzKJ/Jwo8TRcHyHii0=
github.com/go-logr/logr v1.2.2/go.mod h1:jdQByPbusPIv2/zmleS9BjJVeZ6kBagPoEUsqbVz/1A=
github.com/go-logr/logr v1.4.2 h1:6pFjapn8bFcIbiKo3XT4j/BhANplGihG6tvd+8rYgrY=
github.com/go-logr/logr v1.4.2/go.mod h1:9T104GzyrTigFIr8wt5mBrctHMim0Nb2HLGrmQ40KvY=
github.com/go-logr/stdr v1.2.2 h1:hSWxHoqTgW2S2qGc0LTAI563KZ5YKYRhT3MFKZMbjag=
github.com/go-logr/stdr v1.2.2/go.mod h1:mMo/vtBO5dYbehREoey6XUKy/eSumjCCveDpRre4VKE=
github.com/go-viper/mapstructure/v2 v2.2.1 h1:ZAaOCxANMuZx5RCeg0mBdEZk7DZasvvZIxtHqx8aGss=
github.com/go-viper/mapstructure/v2 v2.2.1/go.mod h1:oJDH3BJKyqBA2TXFhDsKDGDTlndYOZ6rGS0BRZIxGhM=
github.com/gogo/protobuf v1.3.2 h1:Ov1cvc58UF3b5XjBnZv7+opcTcQFZebYjWzi34vdm4Q=
github.com/gogo/protobuf v1.3.2/go.mod h1:P1XiOD3dCwIKUDQYPy72D8LYyHL2YPYrpS2s69NZV8Q=
github.com/google/go-cmp v0.5.2/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.7.0 h1:wk8382ETsv4JYUZwIsn6YpYiWiBsYLSJiTsyBybVuN8=
github.com/google/go-cmp v0.7.0/go.mod h1:pXiqmnSA92OHEEa9HXL2W4E7lf9JzCmGVUdgjX3N/iU=
github.com/google/go-github/v64 v64.0.0 h1:4G61sozmY3eiPAjjoOHponXDBONm+utovTKbyUb2Qdg=
github.com/google/go-github/v64 v64.0.0/go.mod h1:xB3vqMQNdHzilXBiO2I+M7iEFtHf+DP/omBOv6tQzVo=
github.com/google/go-github/v69 v69.2.0 h1:wR+Wi/fN2zdUx9YxSmYE0ktiX9IAR/BeePzeaUUbEHE=
github.com/google/go-github/v69 v69.2.0/go.mod h1:xne4jymxLR6Uj9b7J7PyTpkMYstEMMwGZa0Aehh1azM=
github.com/google/go-querystring v1.1.0 h1:AnCroh3fv4ZBgVIf1Iwtovgjaw/GiKJo8M8yD/fhyJ8=
github.com/google/go-querystring v1.1.0/go.mod h1:Kcdr2DB4koayq7X8pmAG4sNG59So17icRSOU623lUBU=
github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/gorilla/mux v1.8.0 h1:i40aqfkR1h2SlN9hojwV5ZA91wcXFOvkdNIeFDP5koI=
github.com/gorilla/mux v1.8.0/go.mod h1:DVbg23sWSpFRCP0SfiEN6jmj59UnW/n46BH5rLB71So=
github.com/grpc-ecosystem/grpc-gateway/v2 v2.25.1 h1:VNqngBF40hVlDloBruUehVYC3ArSgIyScOAyMRqBxRg=
github.com/grpc-ecosystem/grpc-gateway/v2 v2.25.1/go.mod h1:RBRO7fro65R6tjKzYgLAFo0t1QEXY1Dp+i/bvpRiqiQ=
github.com/inconshreveable/mousetrap v1.1.0 h1:wN+x4NVGpMsO7ErUn/mUI3vEoE6Jt13X2s0bqwp9tc8=
github.com/inconshreveable/mousetrap v1.1.0/go.mod h1:vpF70FUmC8bwa3OWnCshd2FqLfsEA9PFc4w1p2J65bw=
github.com/kisielk/errcheck v1.5.0/go.mod h1:pFxgyoBC7bSaBwPgfKdkLd5X25qrDl4LWUI2bnpBCr8=
github.com/kisielk/gotool v1.0.0/go.mod h1:XhKaO+MFFWcvkIS/tQcRk01m1F5IRFswLeQ+oQHNcck=
github.com/kr/pretty v0.3.1 h1:flRD4NNwYAUpkphVc1HcthR4KEIFJ65n8Mw5qdRn3LE=
github.com/kr/pretty v0.3.1/go.mod h1:hoEshYVHaxMs3cyo3Yncou5ZscifuDolrwPKZanG3xk=
github.com/kr/text v0.2.0 h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=
github.com/kr/text v0.2.0/go.mod h1:eLer722TekiGuMkidMxC/pM04lWEeraHUUmBw8l2grE=
github.com/mark3labs/mcp-go v0.20.1 h1:E1Bbx9K8d8kQmDZ1QHblM38c7UU2evQ2LlkANk1U/zw=
github.com/mark3labs/mcp-go v0.20.1/go.mod h1:KmJndYv7GIgcPVwEKJjNcbhVQ+hJGJhrCCB/9xITzpE=
github.com/migueleliasweb/go-github-mock v1.1.0 h1:GKaOBPsrPGkAKgtfuWY8MclS1xR6MInkx1SexJucMwE=
github.com/migueleliasweb/go-github-mock v1.1.0/go.mod h1:pYe/XlGs4BGMfRY4vmeixVsODHnVDDhJ9zoi0qzSMHc=
github.com/moby/docker-image-spec v1.3.1 h1:jMKff3w6PgbfSa69GfNg+zN/XLhfXJGnEx3Nl2EsFP0=
github.com/moby/docker-image-spec v1.3.1/go.mod h1:eKmb5VW8vQEh/BAr2yvVNvuiJuY6UIocYsFu/DxxRpo=
github.com/moby/term v0.5.0 h1:xt8Q1nalod/v7BqbG21f8mQPqH+xAaC9C3N3wfWbVP0=
github.com/moby/term v0.5.0/go.mod h1:8FzsFHVUBGZdbDsJw/ot+X+d5HLUbvklYLJ9uGfcI3Y=
github.com/morikuni/aec v1.0.0 h1:nP9CBfwrvYnBRgY6qfDQkygYDmYwOilePFkwzv4dU8A=
github.com/morikuni/aec v1.0.0/go.mod h1:BbKIizmSmc5MMPqRYbxO4ZU0S0+P200+tUnFx7PXmsc=
github.com/opencontainers/go-digest v1.0.0 h1:apOUWs51W5PlhuyGyz9FCeeBIOUDA/6nW8Oi/yOhh5U=
github.com/opencontainers/go-digest v1.0.0/go.mod h1:0JzlMkj0TRzQZfJkVvzbP0HBR3IKzErnv2BNG4W4MAM=
github.com/opencontainers/image-spec v1.1.1 h1:y0fUlFfIZhPF1W537XOLg0/fcx6zcHCJwooC2xJA040=
github.com/opencontainers/image-spec v1.1.1/go.mod h1:qpqAh3Dmcf36wStyyWU+kCeDgrGnAve2nCC8+7h8Q0M=
github.com/pelletier/go-toml/v2 v2.2.3 h1:YmeHyLY8mFWbdkNWwpr+qIL2bEqT0o95WSdkNHvL12M=
github.com/pelletier/go-toml/v2 v2.2.3/go.mod h1:MfCQTFTvCcUyyvvwm1+G6H/jORL20Xlb6rzQu9GuUkc=
github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 h1:Jamvg5psRIccs7FGNTlIRMkT8wgtp5eCXdBlqhYGL6U=
github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/rogpeppe/go-internal v1.13.1 h1:KvO1DLK/DRN07sQ1LQKScxyZJuNnedQ5/wKSR38lUII=
github.com/rogpeppe/go-internal v1.13.1/go.mod h1:uMEvuHeurkdAXX61udpOXGD/AzZDWNMNyH2VO9fmH0o=
github.com/russross/blackfriday/v2 v2.1.0/go.mod h1:+Rmxgy9KzJVeS9/2gXHxylqXiyQDYRxCVz55jmeOWTM=
github.com/sagikazarmark/locafero v0.9.0 h1:GbgQGNtTrEmddYDSAH9QLRyfAHY12md+8YFTqyMTC9k=
github.com/sagikazarmark/locafero v0.9.0/go.mod h1:UBUyz37V+EdMS3hDF3QWIiVr/2dPrx49OMO0Bn0hJqk=
github.com/sirupsen/logrus v1.9.3 h1:dueUQJ1C2q9oE3F7wvmSGAaVtTmUizReu6fjN8uqzbQ=
github.com/sirupsen/logrus v1.9.3/go.mod h1:naHLuLoDiP4jHNo9R0sCBMtWGeIprob74mVsIT4qYEQ=
github.com/sourcegraph/conc v0.3.0 h1:OQTbbt6P72L20UqAkXXuLOj79LfEanQ+YQFNpLA9ySo=
github.com/sourcegraph/conc v0.3.0/go.mod h1:Sdozi7LEKbFPqYX2/J+iBAM6HpqSLTASQIKqDmF7Mt0=
github.com/spf13/afero v1.14.0 h1:9tH6MapGnn/j0eb0yIXiLjERO8RB6xIVZRDCX7PtqWA=
github.com/spf13/afero v1.14.0/go.mod h1:acJQ8t0ohCGuMN3O+Pv0V0hgMxNYDlvdk+VTfyZmbYo=
github.com/spf13/cast v1.7.1 h1:cuNEagBQEHWN1FnbGEjCXL2szYEXqfJPbP2HNUaca9Y=
github.com/spf13/cast v1.7.1/go.mod h1:ancEpBxwJDODSW/UG4rDrAqiKolqNNh2DX3mk86cAdo=
github.com/spf13/cobra v1.9.1 h1:CXSaggrXdbHK9CF+8ywj8Amf7PBRmPCOJugH954Nnlo=
github.com/spf13/cobra v1.9.1/go.mod h1:nDyEzZ8ogv936Cinf6g1RU9MRY64Ir93oCnqb9wxYW0=
github.com/spf13/pflag v1.0.6 h1:jFzHGLGAlb3ruxLB8MhbI6A8+AQX/2eW4qeyNZXNp2o=
github.com/spf13/pflag v1.0.6/go.mod h1:McXfInJRrz4CZXVZOBLb0bTZqETkiAhM9Iw0y3An2Bg=
github.com/spf13/viper v1.20.1 h1:ZMi+z/lvLyPSCoNtFCpqjy0S4kPbirhpTMwl8BkW9X4=
github.com/spf13/viper v1.20.1/go.mod h1:P9Mdzt1zoHIG8m2eZQinpiBjo6kCmZSKBClNNqjJvu4=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/testify v1.7.0/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
github.com/stretchr/testify v1.10.0 h1:Xv5erBjTwe/5IxqUQTdXv5kgmIvbHo3QQyRwhJsOfJA=
github.com/stretchr/testify v1.10.0/go.mod h1:r2ic/lqez/lEtzL7wO/rwa5dbSLXVDPFyf8C91i36aY=
github.com/subosito/gotenv v1.6.0 h1:9NlTDc1FTs4qu0DDq7AEtTPNw6SVm7uBMsUCUjABIf8=
github.com/subosito/gotenv v1.6.0/go.mod h1:Dk4QP5c2W3ibzajGcXpNraDfq2IrhjMIvMSWPKKo0FU=
github.com/yosida95/uritemplate/v3 v3.0.2 h1:Ed3Oyj9yrmi9087+NczuL5BwkIc4wvTb5zIM+UJPGz4=
github.com/yosida95/uritemplate/v3 v3.0.2/go.mod h1:ILOh0sOhIJR3+L/8afwt/kE++YT040gmv5BQTMR2HP4=
github.com/yuin/goldmark v1.1.27/go.mod h1:3hX8gzYuyVAZsxl0MRgGTJEmQBFcNTphYh9decYSb74=
github.com/yuin/goldmark v1.2.1/go.mod h1:3hX8gzYuyVAZsxl0MRgGTJEmQBFcNTphYh9decYSb74=
go.opentelemetry.io/auto/sdk v1.1.0 h1:cH53jehLUN6UFLY71z+NDOiNJqDdPRaXzTel0sJySYA=
go.opentelemetry.io/auto/sdk v1.1.0/go.mod h1:3wSPjt5PWp2RhlCcmmOial7AvC4DQqZb7a7wCow3W8A=
go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 h1:jq9TW8u3so/bN+JPT166wjOI6/vQPF6Xe7nMNIltagk=
go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0/go.mod h1:p8pYQP+m5XfbZm9fxtSKAbM6oIllS7s2AfxrChvc7iw=
go.opentelemetry.io/otel v1.35.0 h1:xKWKPxrxB6OtMCbmMY021CqC45J+3Onta9MqjhnusiQ=
go.opentelemetry.io/otel v1.35.0/go.mod h1:UEqy8Zp11hpkUrL73gSlELM0DupHoiq72dR+Zqel/+Y=
go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.35.0 h1:1fTNlAIJZGWLP5FVu0fikVry1IsiUnXjf7QFvoNN3Xw=
go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.35.0/go.mod h1:zjPK58DtkqQFn+YUMbx0M2XV3QgKU0gS9LeGohREyK4=
go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.19.0 h1:IeMeyr1aBvBiPVYihXIaeIZba6b8E1bYp7lbdxK8CQg=
go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.19.0/go.mod h1:oVdCUtjq9MK9BlS7TtucsQwUcXcymNiEDjgDD2jMtZU=
go.opentelemetry.io/otel/metric v1.35.0 h1:0znxYu2SNyuMSQT4Y9WDWej0VpcsxkuklLa4/siN90M=
go.opentelemetry.io/otel/metric v1.35.0/go.mod h1:nKVFgxBZ2fReX6IlyW28MgZojkoAkJGaE8CpgeAU3oE=
go.opentelemetry.io/otel/sdk v1.35.0 h1:iPctf8iprVySXSKJffSS79eOjl9pvxV9ZqOWT0QejKY=
go.opentelemetry.io/otel/sdk v1.35.0/go.mod h1:+ga1bZliga3DxJ3CQGg3updiaAJoNECOgJREo9KHGQg=
go.opentelemetry.io/otel/trace v1.35.0 h1:dPpEfJu1sDIqruz7BHFG3c7528f6ddfSWfFDVt/xgMs=
go.opentelemetry.io/otel/trace v1.35.0/go.mod h1:WUk7DtFp1Aw2MkvqGdwiXYDZZNvA/1J8o6xRXLrIkyc=
go.opentelemetry.io/proto/otlp v1.5.0 h1:xJvq7gMzB31/d406fB8U5CBdyQGw4P399D1aQWU/3i4=
go.opentelemetry.io/proto/otlp v1.5.0/go.mod h1:keN8WnHxOy8PG0rQZjJJ5A2ebUoafqWp0eVQ4yIXvJ4=
go.uber.org/multierr v1.11.0 h1:blXXJkSxSSfBVBlC76pxqeO+LN3aDfLQo+309xJstO0=
go.uber.org/multierr v1.11.0/go.mod h1:20+QtiLqy0Nd6FdQB9TLXag12DsQkrbs3htMFfDN80Y=
golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2/go.mod h1:djNgcEr1/C05ACkg1iLfiJU5Ep61QUkGW8qpdssI0+w=
golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550/go.mod h1:yigFU9vqHzYiE8UmvKecakEJjdnWj3jj499lnFckfCI=
golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9/go.mod h1:LzIPMQfyMNhhGPhUkYOs5KpL4U8rLKemX1yGLhDgUto=
golang.org/x/mod v0.2.0/go.mod h1:s0Qsj1ACt9ePp/hMypM3fl4fZqREWJwdYDEqhRiZZUA=
golang.org/x/mod v0.3.0/go.mod h1:s0Qsj1ACt9ePp/hMypM3fl4fZqREWJwdYDEqhRiZZUA=
golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3/go.mod h1:t9HGtf8HONx5eT2rtn7q6eTqICYqUVnKs3thJo3Qplg=
golang.org/x/net v0.0.0-20190620200207-3b0461eec859/go.mod h1:z5CRVTTTmAJ677TzLLGU+0bjPO0LkuOLi4/5GtJWs/s=
golang.org/x/net v0.0.0-20200226121028-0de0cce0169b/go.mod h1:z5CRVTTTmAJ677TzLLGU+0bjPO0LkuOLi4/5GtJWs/s=
golang.org/x/net v0.0.0-20201021035429-f5854403a974/go.mod h1:sp8m0HH+o8qH0wwXwYZr8TS3Oi6o0r6Gce1SSxlDquU=
golang.org/x/net v0.33.0 h1:74SYHlV8BIgHIFC/LrYkOGIwL19eTYXQ5wc6TBuO36I=
golang.org/x/net v0.33.0/go.mod h1:HXLR5J+9DxmrqMwG9qjGCxZ+zKXxBru04zlTvWlWuN4=
golang.org/x/sync v0.0.0-20190423024810-112230192c58/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a/go.mod h1:STP8DvDyc/dI5b8T5hshtkjS+E42TnysNCUPdjciGhY=
golang.org/x/sys v0.0.0-20190412213103-97732733099d/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.31.0 h1:ioabZlmFYtWhL+TRYpcnNlLwhyxaM9kWTDEmfnprqik=
golang.org/x/sys v0.31.0/go.mod h1:BJP2sWEmIv4KK5OTEluFJCKSidICx8ciO85XgH3Ak8k=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
golang.org/x/text v0.3.3/go.mod h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ=
golang.org/x/text v0.23.0 h1:D71I7dUrlY+VX0gQShAThNGHFxZ13dGLBHQLVl1mJlY=
golang.org/x/text v0.23.0/go.mod h1:/BLNzu4aZCJ1+kcD0DNRotWKage4q2rGVAg4o22unh4=
golang.org/x/time v0.5.0 h1:o7cqy6amK/52YcAKIPlM3a+Fpj35zvRj2TP+e1xFSfk=
golang.org/x/time v0.5.0/go.mod h1:3BpzKBy/shNhVucY/MWOyx10tF3SFh9QdLuxbVysPQM=
golang.org/x/tools v0.0.0-20180917221912-90fa682c2a6e/go.mod h1:n7NCudcB/nEzxVGmLbDWY5pfWTLqBcC2KZ6jyYvM4mQ=
golang.org/x/tools v0.0.0-20191119224855-298f0cb1881e/go.mod h1:b+2E5dAYhXwXZwtnZ6UAqBI28+e2cm9otk0dWdXHAEo=
golang.org/x/tools v0.0.0-20200619180055-7c47624df98f/go.mod h1:EkVYQZoAsY45+roYkvgYkIh4xh/qjgUK9TdY2XT94GE=
golang.org/x/tools v0.0.0-20210106214847-113979e3529a/go.mod h1:emZCQorbCU4vsT4fOWvOPXz4eW1wZW4PmDk9uLelYpA=
golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
google.golang.org/genproto/googleapis/api v0.0.0-20250102185135-69823020774d h1:H8tOf8XM88HvKqLTxe755haY6r1fqqzLbEnfrmLXlSA=
google.golang.org/genproto/googleapis/api v0.0.0-20250102185135-69823020774d/go.mod h1:2v7Z7gP2ZUOGsaFyxATQSRoBnKygqVq2Cwnvom7QiqY=
google.golang.org/genproto/googleapis/rpc v0.0.0-20250102185135-69823020774d h1:xJJRGY7TJcvIlpSrN3K6LAWgNFUILlO+OMAqtg9aqnw=
google.golang.org/genproto/googleapis/rpc v0.0.0-20250102185135-69823020774d/go.mod h1:3ENsm/5D1mzDyhpzeRi1NR784I0BcofWBoSc5QqqMK4=
google.golang.org/grpc v1.69.2 h1:U3S9QEtbXC0bYNvRtcoklF3xGtLViumSYxWykJS+7AU=
google.golang.org/grpc v1.69.2/go.mod h1:vyjdE6jLBI76dgpDojsFGNaHlxdjXN9ghpnd2o7JGZ4=
google.golang.org/protobuf v1.36.5 h1:tPhr+woSbjfYvY6/GPufUoYizxw1cF/yFoxJ2fmpwlM=
google.golang.org/protobuf v1.36.5/go.mod h1:9fA7Ob0pmnwhb644+1+CVWFRbNajQ6iRojtC/QF5bRE=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c h1:Hei/4ADfdWqJk1ZMxUNpqntNwaWcugrBjAiHlqqRiVk=
gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c/go.mod h1:JHkPIbrfpd72SG/EVd6muEfDQjcINNoR0C8j2r3qZ4Q=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gotest.tools/v3 v3.5.1 h1:EENdUnS3pdur5nybKYIh2Vfgc8IUNBjxDPSjtiJcOzU=
gotest.tools/v3 v3.5.1/go.mod h1:isy3WKz7GK6uNw/sbHzfKBLvlvXwUyV06n6brMxxopU=
```

---

## `pkg/github/code_scanning.go`

```go
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func GetCodeScanningAlert(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_code_scanning_alert",
			mcp.WithDescription(t("TOOL_GET_CODE_SCANNING_ALERT_DESCRIPTION", "Get details of a specific code scanning alert in a GitHub repository.")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("The owner of the repository."),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("The name of the repository."),
			),
			mcp.WithNumber("alertNumber",
				mcp.Required(),
				mcp.Description("The number of the alert."),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			alertNumber, err := RequiredInt(request, "alertNumber")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}

			alert, resp, err := client.CodeScanning.GetAlert(ctx, owner, repo, int64(alertNumber))
			if err != nil {
				return nil, fmt.Errorf("failed to get alert: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get alert: %s", string(body))), nil
			}

			r, err := json.Marshal(alert)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal alert: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

func ListCodeScanningAlerts(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("list_code_scanning_alerts",
			mcp.WithDescription(t("TOOL_LIST_CODE_SCANNING_ALERTS_DESCRIPTION", "List code scanning alerts in a GitHub repository.")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("The owner of the repository."),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("The name of the repository."),
			),
			mcp.WithString("ref",
				mcp.Description("The Git reference for the results you want to list."),
			),
			mcp.WithString("state",
				mcp.Description("State of the code scanning alerts to list. Set to closed to list only closed code scanning alerts. Default: open"),
				mcp.DefaultString("open"),
			),
			mcp.WithString("severity",
				mcp.Description("Only code scanning alerts with this severity will be returned. Possible values are: critical, high, medium, low, warning, note, error."),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			ref, err := OptionalParam[string](request, "ref")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			state, err := OptionalParam[string](request, "state")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			severity, err := OptionalParam[string](request, "severity")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			alerts, resp, err := client.CodeScanning.ListAlertsForRepo(ctx, owner, repo, &github.AlertListOptions{Ref: ref, State: state, Severity: severity})
			if err != nil {
				return nil, fmt.Errorf("failed to list alerts: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to list alerts: %s", string(body))), nil
			}

			r, err := json.Marshal(alerts)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal alerts: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}
```

---

## `pkg/github/code_scanning_test.go`

```go
package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetCodeScanningAlert(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := GetCodeScanningAlert(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_code_scanning_alert", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "alertNumber")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "alertNumber"})

	// Setup mock alert for success case
	mockAlert := &github.Alert{
		Number:  github.Ptr(42),
		State:   github.Ptr("open"),
		Rule:    &github.Rule{ID: github.Ptr("test-rule"), Description: github.Ptr("Test Rule Description")},
		HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/42"),
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedAlert  *github.Alert
		expectedErrMsg string
	}{
		{
			name: "successful alert fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber,
					mockAlert,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"alertNumber": float64(42),
			},
			expectError:   false,
			expectedAlert: mockAlert,
		},
		{
			name: "alert fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"alertNumber": float64(9999),
			},
			expectError:    true,
			expectedErrMsg: "failed to get alert",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetCodeScanningAlert(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedAlert github.Alert
			err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
			assert.NoError(t, err)
			assert.Equal(t, *tc.expectedAlert.Number, *returnedAlert.Number)
			assert.Equal(t, *tc.expectedAlert.State, *returnedAlert.State)
			assert.Equal(t, *tc.expectedAlert.Rule.ID, *returnedAlert.Rule.ID)
			assert.Equal(t, *tc.expectedAlert.HTMLURL, *returnedAlert.HTMLURL)

		})
	}
}

func Test_ListCodeScanningAlerts(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := ListCodeScanningAlerts(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "list_code_scanning_alerts", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "ref")
	assert.Contains(t, tool.InputSchema.Properties, "state")
	assert.Contains(t, tool.InputSchema.Properties, "severity")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo"})

	// Setup mock alerts for success case
	mockAlerts := []*github.Alert{
		{
			Number:  github.Ptr(42),
			State:   github.Ptr("open"),
			Rule:    &github.Rule{ID: github.Ptr("test-rule-1"), Description: github.Ptr("Test Rule 1")},
			HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/42"),
		},
		{
			Number:  github.Ptr(43),
			State:   github.Ptr("fixed"),
			Rule:    &github.Rule{ID: github.Ptr("test-rule-2"), Description: github.Ptr("Test Rule 2")},
			HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/43"),
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedAlerts []*github.Alert
		expectedErrMsg string
	}{
		{
			name: "successful alerts listing",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposCodeScanningAlertsByOwnerByRepo,
					expectQueryParams(t, map[string]string{
						"ref":      "main",
						"state":    "open",
						"severity": "high",
					}).andThen(
						mockResponse(t, http.StatusOK, mockAlerts),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":    "owner",
				"repo":     "repo",
				"ref":      "main",
				"state":    "open",
				"severity": "high",
			},
			expectError:    false,
			expectedAlerts: mockAlerts,
		},
		{
			name: "alerts listing fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposCodeScanningAlertsByOwnerByRepo,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte(`{"message": "Unauthorized access"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
			},
			expectError:    true,
			expectedErrMsg: "failed to list alerts",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := ListCodeScanningAlerts(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedAlerts []*github.Alert
			err = json.Unmarshal([]byte(textContent.Text), &returnedAlerts)
			assert.NoError(t, err)
			assert.Len(t, returnedAlerts, len(tc.expectedAlerts))
			for i, alert := range returnedAlerts {
				assert.Equal(t, *tc.expectedAlerts[i].Number, *alert.Number)
				assert.Equal(t, *tc.expectedAlerts[i].State, *alert.State)
				assert.Equal(t, *tc.expectedAlerts[i].Rule.ID, *alert.Rule.ID)
				assert.Equal(t, *tc.expectedAlerts[i].HTMLURL, *alert.HTMLURL)
			}
		})
	}
}
```

---

## `pkg/github/context_tools.go`

```go
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// GetMe creates a tool to get details of the authenticated user.
func GetMe(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_me",
			mcp.WithDescription(t("TOOL_GET_ME_DESCRIPTION", "Get details of the authenticated GitHub user. Use this when a request include \"me\", \"my\"...")),
			mcp.WithString("reason",
				mcp.Description("Optional: reason the session was created"),
			),
		),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			user, resp, err := client.Users.Get(ctx, "")
			if err != nil {
				return nil, fmt.Errorf("failed to get user: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get user: %s", string(body))), nil
			}

			r, err := json.Marshal(user)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal user: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}
```

---

## `pkg/github/context_tools_test.go`

```go
package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetMe(t *testing.T) {
	// Verify tool definition
	mockClient := github.NewClient(nil)
	tool, _ := GetMe(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_me", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "reason")
	assert.Empty(t, tool.InputSchema.Required) // No required parameters

	// Setup mock user response
	mockUser := &github.User{
		Login:     github.Ptr("testuser"),
		Name:      github.Ptr("Test User"),
		Email:     github.Ptr("test@example.com"),
		Bio:       github.Ptr("GitHub user for testing"),
		Company:   github.Ptr("Test Company"),
		Location:  github.Ptr("Test Location"),
		HTMLURL:   github.Ptr("https://github.com/testuser"),
		CreatedAt: &github.Timestamp{Time: time.Now().Add(-365 * 24 * time.Hour)},
		Type:      github.Ptr("User"),
		Plan: &github.Plan{
			Name: github.Ptr("pro"),
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedUser   *github.User
		expectedErrMsg string
	}{
		{
			name: "successful get user",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUser,
					mockUser,
				),
			),
			requestArgs:  map[string]interface{}{},
			expectError:  false,
			expectedUser: mockUser,
		},
		{
			name: "successful get user with reason",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUser,
					mockUser,
				),
			),
			requestArgs: map[string]interface{}{
				"reason": "Testing API",
			},
			expectError:  false,
			expectedUser: mockUser,
		},
		{
			name: "get user fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetUser,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte(`{"message": "Unauthorized"}`))
					}),
				),
			),
			requestArgs:    map[string]interface{}{},
			expectError:    true,
			expectedErrMsg: "failed to get user",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetMe(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse result and get text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedUser github.User
			err = json.Unmarshal([]byte(textContent.Text), &returnedUser)
			require.NoError(t, err)

			// Verify user details
			assert.Equal(t, *tc.expectedUser.Login, *returnedUser.Login)
			assert.Equal(t, *tc.expectedUser.Name, *returnedUser.Name)
			assert.Equal(t, *tc.expectedUser.Email, *returnedUser.Email)
			assert.Equal(t, *tc.expectedUser.Bio, *returnedUser.Bio)
			assert.Equal(t, *tc.expectedUser.HTMLURL, *returnedUser.HTMLURL)
			assert.Equal(t, *tc.expectedUser.Type, *returnedUser.Type)
		})
	}
}
```

---

## `pkg/github/dynamic_tools.go`

```go
package github

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/github/github-mcp-server/pkg/toolsets"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func ToolsetEnum(toolsetGroup *toolsets.ToolsetGroup) mcp.PropertyOption {
	toolsetNames := make([]string, 0, len(toolsetGroup.Toolsets))
	for name := range toolsetGroup.Toolsets {
		toolsetNames = append(toolsetNames, name)
	}
	return mcp.Enum(toolsetNames...)
}

func EnableToolset(s *server.MCPServer, toolsetGroup *toolsets.ToolsetGroup, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("enable_toolset",
			mcp.WithDescription(t("TOOL_ENABLE_TOOLSET_DESCRIPTION", "Enable one of the sets of tools the GitHub MCP server provides, use get_toolset_tools and list_available_toolsets first to see what this will enable")),
			mcp.WithString("toolset",
				mcp.Required(),
				mcp.Description("The name of the toolset to enable"),
				ToolsetEnum(toolsetGroup),
			),
		),
		func(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// We need to convert the toolsets back to a map for JSON serialization
			toolsetName, err := requiredParam[string](request, "toolset")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			toolset := toolsetGroup.Toolsets[toolsetName]
			if toolset == nil {
				return mcp.NewToolResultError(fmt.Sprintf("Toolset %s not found", toolsetName)), nil
			}
			if toolset.Enabled {
				return mcp.NewToolResultText(fmt.Sprintf("Toolset %s is already enabled", toolsetName)), nil
			}

			toolset.Enabled = true

			// caution: this currently affects the global tools and notifies all clients:
			//
			// Send notification to all initialized sessions
			// s.sendNotificationToAllClients("notifications/tools/list_changed", nil)
			s.AddTools(toolset.GetActiveTools()...)

			return mcp.NewToolResultText(fmt.Sprintf("Toolset %s enabled", toolsetName)), nil
		}
}

func ListAvailableToolsets(toolsetGroup *toolsets.ToolsetGroup, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("list_available_toolsets",
			mcp.WithDescription(t("TOOL_LIST_AVAILABLE_TOOLSETS_DESCRIPTION", "List all available toolsets this GitHub MCP server can offer, providing the enabled status of each. Use this when a task could be achieved with a GitHub tool and the currently available tools aren't enough. Call get_toolset_tools with these toolset names to discover specific tools you can call")),
		),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// We need to convert the toolsetGroup back to a map for JSON serialization

			payload := []map[string]string{}

			for name, ts := range toolsetGroup.Toolsets {
				{
					t := map[string]string{
						"name":              name,
						"description":       ts.Description,
						"can_enable":        "true",
						"currently_enabled": fmt.Sprintf("%t", ts.Enabled),
					}
					payload = append(payload, t)
				}
			}

			r, err := json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal features: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

func GetToolsetsTools(toolsetGroup *toolsets.ToolsetGroup, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_toolset_tools",
			mcp.WithDescription(t("TOOL_GET_TOOLSET_TOOLS_DESCRIPTION", "Lists all the capabilities that are enabled with the specified toolset, use this to get clarity on whether enabling a toolset would help you to complete a task")),
			mcp.WithString("toolset",
				mcp.Required(),
				mcp.Description("The name of the toolset you want to get the tools for"),
				ToolsetEnum(toolsetGroup),
			),
		),
		func(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// We need to convert the toolsetGroup back to a map for JSON serialization
			toolsetName, err := requiredParam[string](request, "toolset")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			toolset := toolsetGroup.Toolsets[toolsetName]
			if toolset == nil {
				return mcp.NewToolResultError(fmt.Sprintf("Toolset %s not found", toolsetName)), nil
			}
			payload := []map[string]string{}

			for _, st := range toolset.GetAvailableTools() {
				tool := map[string]string{
					"name":        st.Tool.Name,
					"description": st.Tool.Description,
					"can_enable":  "true",
					"toolset":     toolsetName,
				}
				payload = append(payload, tool)
			}

			r, err := json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal features: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}
```

---

## `pkg/github/helper_test.go`

```go
package github

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// expectQueryParams is a helper function to create a partial mock that expects a
// request with the given query parameters, with the ability to chain a response handler.
func expectQueryParams(t *testing.T, expectedQueryParams map[string]string) *partialMock {
	return &partialMock{
		t:                   t,
		expectedQueryParams: expectedQueryParams,
	}
}

// expectRequestBody is a helper function to create a partial mock that expects a
// request with the given body, with the ability to chain a response handler.
func expectRequestBody(t *testing.T, expectedRequestBody any) *partialMock {
	return &partialMock{
		t:                   t,
		expectedRequestBody: expectedRequestBody,
	}
}

type partialMock struct {
	t                   *testing.T
	expectedQueryParams map[string]string
	expectedRequestBody any
}

func (p *partialMock) andThen(responseHandler http.HandlerFunc) http.HandlerFunc {
	p.t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if p.expectedRequestBody != nil {
			var unmarshaledRequestBody any
			err := json.NewDecoder(r.Body).Decode(&unmarshaledRequestBody)
			require.NoError(p.t, err)

			require.Equal(p.t, p.expectedRequestBody, unmarshaledRequestBody)
		}

		if p.expectedQueryParams != nil {
			require.Equal(p.t, len(p.expectedQueryParams), len(r.URL.Query()))
			for k, v := range p.expectedQueryParams {
				require.Equal(p.t, v, r.URL.Query().Get(k))
			}
		}

		responseHandler(w, r)
	}
}

// mockResponse is a helper function to create a mock HTTP response handler
// that returns a specified status code and marshaled body.
func mockResponse(t *testing.T, code int, body interface{}) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		b, err := json.Marshal(body)
		require.NoError(t, err)
		_, _ = w.Write(b)
	}
}

// createMCPRequest is a helper function to create a MCP request with the given arguments.
func createMCPRequest(args map[string]interface{}) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments,omitempty"`
			Meta      *struct {
				ProgressToken mcp.ProgressToken `json:"progressToken,omitempty"`
			} `json:"_meta,omitempty"`
		}{
			Arguments: args,
		},
	}
}

// getTextResult is a helper function that returns a text result from a tool call.
func getTextResult(t *testing.T, result *mcp.CallToolResult) mcp.TextContent {
	t.Helper()
	assert.NotNil(t, result)
	require.Len(t, result.Content, 1)
	require.IsType(t, mcp.TextContent{}, result.Content[0])
	textContent := result.Content[0].(mcp.TextContent)
	assert.Equal(t, "text", textContent.Type)
	return textContent
}

func TestOptionalParamOK(t *testing.T) {
	tests := []struct {
		name        string
		args        map[string]interface{}
		paramName   string
		expectedVal interface{}
		expectedOk  bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "present and correct type (string)",
			args:        map[string]interface{}{"myParam": "hello"},
			paramName:   "myParam",
			expectedVal: "hello",
			expectedOk:  true,
			expectError: false,
		},
		{
			name:        "present and correct type (bool)",
			args:        map[string]interface{}{"myParam": true},
			paramName:   "myParam",
			expectedVal: true,
			expectedOk:  true,
			expectError: false,
		},
		{
			name:        "present and correct type (number)",
			args:        map[string]interface{}{"myParam": float64(123)},
			paramName:   "myParam",
			expectedVal: float64(123),
			expectedOk:  true,
			expectError: false,
		},
		{
			name:        "present but wrong type (string expected, got bool)",
			args:        map[string]interface{}{"myParam": true},
			paramName:   "myParam",
			expectedVal: "",   // Zero value for string
			expectedOk:  true, // ok is true because param exists
			expectError: true,
			errorMsg:    "parameter myParam is not of type string, is bool",
		},
		{
			name:        "present but wrong type (bool expected, got string)",
			args:        map[string]interface{}{"myParam": "true"},
			paramName:   "myParam",
			expectedVal: false, // Zero value for bool
			expectedOk:  true,  // ok is true because param exists
			expectError: true,
			errorMsg:    "parameter myParam is not of type bool, is string",
		},
		{
			name:        "parameter not present",
			args:        map[string]interface{}{"anotherParam": "value"},
			paramName:   "myParam",
			expectedVal: "", // Zero value for string
			expectedOk:  false,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := createMCPRequest(tc.args)

			// Test with string type assertion
			if _, isString := tc.expectedVal.(string); isString || tc.errorMsg == "parameter myParam is not of type string, is bool" {
				val, ok, err := OptionalParamOK[string](request, tc.paramName)
				if tc.expectError {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tc.errorMsg)
					assert.Equal(t, tc.expectedOk, ok)   // Check ok even on error
					assert.Equal(t, tc.expectedVal, val) // Check zero value on error
				} else {
					require.NoError(t, err)
					assert.Equal(t, tc.expectedOk, ok)
					assert.Equal(t, tc.expectedVal, val)
				}
			}

			// Test with bool type assertion
			if _, isBool := tc.expectedVal.(bool); isBool || tc.errorMsg == "parameter myParam is not of type bool, is string" {
				val, ok, err := OptionalParamOK[bool](request, tc.paramName)
				if tc.expectError {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tc.errorMsg)
					assert.Equal(t, tc.expectedOk, ok)   // Check ok even on error
					assert.Equal(t, tc.expectedVal, val) // Check zero value on error
				} else {
					require.NoError(t, err)
					assert.Equal(t, tc.expectedOk, ok)
					assert.Equal(t, tc.expectedVal, val)
				}
			}

			// Test with float64 type assertion (for number case)
			if _, isFloat := tc.expectedVal.(float64); isFloat {
				val, ok, err := OptionalParamOK[float64](request, tc.paramName)
				if tc.expectError {
					// This case shouldn't happen for float64 in the defined tests
					require.Fail(t, "Unexpected error case for float64")
				} else {
					require.NoError(t, err)
					assert.Equal(t, tc.expectedOk, ok)
					assert.Equal(t, tc.expectedVal, val)
				}
			}
		})
	}
}
```

---

## `pkg/github/issues.go`

```go
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// GetIssue creates a tool to get details of a specific issue in a GitHub repository.
func GetIssue(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_issue",
			mcp.WithDescription(t("TOOL_GET_ISSUE_DESCRIPTION", "Get details of a specific issue in a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("The owner of the repository"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("The name of the repository"),
			),
			mcp.WithNumber("issue_number",
				mcp.Required(),
				mcp.Description("The number of the issue"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			issueNumber, err := RequiredInt(request, "issue_number")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			issue, resp, err := client.Issues.Get(ctx, owner, repo, issueNumber)
			if err != nil {
				return nil, fmt.Errorf("failed to get issue: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get issue: %s", string(body))), nil
			}

			r, err := json.Marshal(issue)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal issue: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// AddIssueComment creates a tool to add a comment to an issue.
func AddIssueComment(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("add_issue_comment",
			mcp.WithDescription(t("TOOL_ADD_ISSUE_COMMENT_DESCRIPTION", "Add a comment to an existing issue")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("issue_number",
				mcp.Required(),
				mcp.Description("Issue number to comment on"),
			),
			mcp.WithString("body",
				mcp.Required(),
				mcp.Description("Comment text"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			issueNumber, err := RequiredInt(request, "issue_number")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			body, err := requiredParam[string](request, "body")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			comment := &github.IssueComment{
				Body: github.Ptr(body),
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			createdComment, resp, err := client.Issues.CreateComment(ctx, owner, repo, issueNumber, comment)
			if err != nil {
				return nil, fmt.Errorf("failed to create comment: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusCreated {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to create comment: %s", string(body))), nil
			}

			r, err := json.Marshal(createdComment)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// SearchIssues creates a tool to search for issues and pull requests.
func SearchIssues(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("search_issues",
			mcp.WithDescription(t("TOOL_SEARCH_ISSUES_DESCRIPTION", "Search for issues and pull requests across GitHub repositories")),
			mcp.WithString("q",
				mcp.Required(),
				mcp.Description("Search query using GitHub issues search syntax"),
			),
			mcp.WithString("sort",
				mcp.Description("Sort field (comments, reactions, created, etc.)"),
				mcp.Enum(
					"comments",
					"reactions",
					"reactions-+1",
					"reactions--1",
					"reactions-smile",
					"reactions-thinking_face",
					"reactions-heart",
					"reactions-tada",
					"interactions",
					"created",
					"updated",
				),
			),
			mcp.WithString("order",
				mcp.Description("Sort order ('asc' or 'desc')"),
				mcp.Enum("asc", "desc"),
			),
			WithPagination(),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			query, err := requiredParam[string](request, "q")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			sort, err := OptionalParam[string](request, "sort")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			order, err := OptionalParam[string](request, "order")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pagination, err := OptionalPaginationParams(request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.SearchOptions{
				Sort:  sort,
				Order: order,
				ListOptions: github.ListOptions{
					PerPage: pagination.perPage,
					Page:    pagination.page,
				},
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			result, resp, err := client.Search.Issues(ctx, query, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to search issues: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to search issues: %s", string(body))), nil
			}

			r, err := json.Marshal(result)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// CreateIssue creates a tool to create a new issue in a GitHub repository.
func CreateIssue(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("create_issue",
			mcp.WithDescription(t("TOOL_CREATE_ISSUE_DESCRIPTION", "Create a new issue in a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("title",
				mcp.Required(),
				mcp.Description("Issue title"),
			),
			mcp.WithString("body",
				mcp.Description("Issue body content"),
			),
			mcp.WithArray("assignees",
				mcp.Description("Usernames to assign to this issue"),
				mcp.Items(
					map[string]interface{}{
						"type": "string",
					},
				),
			),
			mcp.WithArray("labels",
				mcp.Description("Labels to apply to this issue"),
				mcp.Items(
					map[string]interface{}{
						"type": "string",
					},
				),
			),
			mcp.WithNumber("milestone",
				mcp.Description("Milestone number"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			title, err := requiredParam[string](request, "title")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Optional parameters
			body, err := OptionalParam[string](request, "body")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Get assignees
			assignees, err := OptionalStringArrayParam(request, "assignees")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Get labels
			labels, err := OptionalStringArrayParam(request, "labels")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Get optional milestone
			milestone, err := OptionalIntParam(request, "milestone")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			var milestoneNum *int
			if milestone != 0 {
				milestoneNum = &milestone
			}

			// Create the issue request
			issueRequest := &github.IssueRequest{
				Title:     github.Ptr(title),
				Body:      github.Ptr(body),
				Assignees: &assignees,
				Labels:    &labels,
				Milestone: milestoneNum,
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			issue, resp, err := client.Issues.Create(ctx, owner, repo, issueRequest)
			if err != nil {
				return nil, fmt.Errorf("failed to create issue: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusCreated {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to create issue: %s", string(body))), nil
			}

			r, err := json.Marshal(issue)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// ListIssues creates a tool to list and filter repository issues
func ListIssues(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("list_issues",
			mcp.WithDescription(t("TOOL_LIST_ISSUES_DESCRIPTION", "List issues in a GitHub repository with filtering options")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("state",
				mcp.Description("Filter by state ('open', 'closed', 'all')"),
				mcp.Enum("open", "closed", "all"),
			),
			mcp.WithArray("labels",
				mcp.Description("Filter by labels"),
				mcp.Items(
					map[string]interface{}{
						"type": "string",
					},
				),
			),
			mcp.WithString("sort",
				mcp.Description("Sort by ('created', 'updated', 'comments')"),
				mcp.Enum("created", "updated", "comments"),
			),
			mcp.WithString("direction",
				mcp.Description("Sort direction ('asc', 'desc')"),
				mcp.Enum("asc", "desc"),
			),
			mcp.WithString("since",
				mcp.Description("Filter by date (ISO 8601 timestamp)"),
			),
			WithPagination(),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.IssueListByRepoOptions{}

			// Set optional parameters if provided
			opts.State, err = OptionalParam[string](request, "state")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Get labels
			opts.Labels, err = OptionalStringArrayParam(request, "labels")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts.Sort, err = OptionalParam[string](request, "sort")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts.Direction, err = OptionalParam[string](request, "direction")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			since, err := OptionalParam[string](request, "since")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if since != "" {
				timestamp, err := parseISOTimestamp(since)
				if err != nil {
					return mcp.NewToolResultError(fmt.Sprintf("failed to list issues: %s", err.Error())), nil
				}
				opts.Since = timestamp
			}

			if page, ok := request.Params.Arguments["page"].(float64); ok {
				opts.Page = int(page)
			}

			if perPage, ok := request.Params.Arguments["perPage"].(float64); ok {
				opts.PerPage = int(perPage)
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			issues, resp, err := client.Issues.ListByRepo(ctx, owner, repo, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to list issues: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to list issues: %s", string(body))), nil
			}

			r, err := json.Marshal(issues)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal issues: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// UpdateIssue creates a tool to update an existing issue in a GitHub repository.
func UpdateIssue(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("update_issue",
			mcp.WithDescription(t("TOOL_UPDATE_ISSUE_DESCRIPTION", "Update an existing issue in a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("issue_number",
				mcp.Required(),
				mcp.Description("Issue number to update"),
			),
			mcp.WithString("title",
				mcp.Description("New title"),
			),
			mcp.WithString("body",
				mcp.Description("New description"),
			),
			mcp.WithString("state",
				mcp.Description("New state ('open' or 'closed')"),
				mcp.Enum("open", "closed"),
			),
			mcp.WithArray("labels",
				mcp.Description("New labels"),
				mcp.Items(
					map[string]interface{}{
						"type": "string",
					},
				),
			),
			mcp.WithArray("assignees",
				mcp.Description("New assignees"),
				mcp.Items(
					map[string]interface{}{
						"type": "string",
					},
				),
			),
			mcp.WithNumber("milestone",
				mcp.Description("New milestone number"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			issueNumber, err := RequiredInt(request, "issue_number")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Create the issue request with only provided fields
			issueRequest := &github.IssueRequest{}

			// Set optional parameters if provided
			title, err := OptionalParam[string](request, "title")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if title != "" {
				issueRequest.Title = github.Ptr(title)
			}

			body, err := OptionalParam[string](request, "body")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if body != "" {
				issueRequest.Body = github.Ptr(body)
			}

			state, err := OptionalParam[string](request, "state")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if state != "" {
				issueRequest.State = github.Ptr(state)
			}

			// Get labels
			labels, err := OptionalStringArrayParam(request, "labels")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if len(labels) > 0 {
				issueRequest.Labels = &labels
			}

			// Get assignees
			assignees, err := OptionalStringArrayParam(request, "assignees")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if len(assignees) > 0 {
				issueRequest.Assignees = &assignees
			}

			milestone, err := OptionalIntParam(request, "milestone")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if milestone != 0 {
				milestoneNum := milestone
				issueRequest.Milestone = &milestoneNum
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			updatedIssue, resp, err := client.Issues.Edit(ctx, owner, repo, issueNumber, issueRequest)
			if err != nil {
				return nil, fmt.Errorf("failed to update issue: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to update issue: %s", string(body))), nil
			}

			r, err := json.Marshal(updatedIssue)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// GetIssueComments creates a tool to get comments for a GitHub issue.
func GetIssueComments(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_issue_comments",
			mcp.WithDescription(t("TOOL_GET_ISSUE_COMMENTS_DESCRIPTION", "Get comments for a GitHub issue")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("issue_number",
				mcp.Required(),
				mcp.Description("Issue number"),
			),
			mcp.WithNumber("page",
				mcp.Description("Page number"),
			),
			mcp.WithNumber("per_page",
				mcp.Description("Number of records per page"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			issueNumber, err := RequiredInt(request, "issue_number")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			page, err := OptionalIntParamWithDefault(request, "page", 1)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			perPage, err := OptionalIntParamWithDefault(request, "per_page", 30)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.IssueListCommentsOptions{
				ListOptions: github.ListOptions{
					Page:    page,
					PerPage: perPage,
				},
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			comments, resp, err := client.Issues.ListComments(ctx, owner, repo, issueNumber, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to get issue comments: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get issue comments: %s", string(body))), nil
			}

			r, err := json.Marshal(comments)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// parseISOTimestamp parses an ISO 8601 timestamp string into a time.Time object.
// Returns the parsed time or an error if parsing fails.
// Example formats supported: "2023-01-15T14:30:00Z", "2023-01-15"
func parseISOTimestamp(timestamp string) (time.Time, error) {
	if timestamp == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}

	// Try RFC3339 format (standard ISO 8601 with time)
	t, err := time.Parse(time.RFC3339, timestamp)
	if err == nil {
		return t, nil
	}

	// Try simple date format (YYYY-MM-DD)
	t, err = time.Parse("2006-01-02", timestamp)
	if err == nil {
		return t, nil
	}

	// Return error with supported formats
	return time.Time{}, fmt.Errorf("invalid ISO 8601 timestamp: %s (supported formats: YYYY-MM-DDThh:mm:ssZ or YYYY-MM-DD)", timestamp)
}
```

---

## `pkg/github/issues_test.go`

```go
package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetIssue(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := GetIssue(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_issue", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "issue_number")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "issue_number"})

	// Setup mock issue for success case
	mockIssue := &github.Issue{
		Number:  github.Ptr(42),
		Title:   github.Ptr("Test Issue"),
		Body:    github.Ptr("This is a test issue"),
		State:   github.Ptr("open"),
		HTMLURL: github.Ptr("https://github.com/owner/repo/issues/42"),
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedIssue  *github.Issue
		expectedErrMsg string
	}{
		{
			name: "successful issue retrieval",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposIssuesByOwnerByRepoByIssueNumber,
					mockIssue,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(42),
			},
			expectError:   false,
			expectedIssue: mockIssue,
		},
		{
			name: "issue not found",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposIssuesByOwnerByRepoByIssueNumber,
					mockResponse(t, http.StatusNotFound, `{"message": "Issue not found"}`),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(999),
			},
			expectError:    true,
			expectedErrMsg: "failed to get issue",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetIssue(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedIssue github.Issue
			err = json.Unmarshal([]byte(textContent.Text), &returnedIssue)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedIssue.Number, *returnedIssue.Number)
			assert.Equal(t, *tc.expectedIssue.Title, *returnedIssue.Title)
			assert.Equal(t, *tc.expectedIssue.Body, *returnedIssue.Body)
		})
	}
}

func Test_AddIssueComment(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := AddIssueComment(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "add_issue_comment", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "issue_number")
	assert.Contains(t, tool.InputSchema.Properties, "body")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "issue_number", "body"})

	// Setup mock comment for success case
	mockComment := &github.IssueComment{
		ID:   github.Ptr(int64(123)),
		Body: github.Ptr("This is a test comment"),
		User: &github.User{
			Login: github.Ptr("testuser"),
		},
		HTMLURL: github.Ptr("https://github.com/owner/repo/issues/42#issuecomment-123"),
	}

	tests := []struct {
		name            string
		mockedClient    *http.Client
		requestArgs     map[string]interface{}
		expectError     bool
		expectedComment *github.IssueComment
		expectedErrMsg  string
	}{
		{
			name: "successful comment creation",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposIssuesCommentsByOwnerByRepoByIssueNumber,
					mockResponse(t, http.StatusCreated, mockComment),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(42),
				"body":         "This is a test comment",
			},
			expectError:     false,
			expectedComment: mockComment,
		},
		{
			name: "comment creation fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposIssuesCommentsByOwnerByRepoByIssueNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message": "Invalid request"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(42),
				"body":         "",
			},
			expectError:    false,
			expectedErrMsg: "missing required parameter: body",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := AddIssueComment(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := mcp.CallToolRequest{
				Params: struct {
					Name      string                 `json:"name"`
					Arguments map[string]interface{} `json:"arguments,omitempty"`
					Meta      *struct {
						ProgressToken mcp.ProgressToken `json:"progressToken,omitempty"`
					} `json:"_meta,omitempty"`
				}{
					Arguments: tc.requestArgs,
				},
			}

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			if tc.expectedErrMsg != "" {
				require.NotNil(t, result)
				textContent := getTextResult(t, result)
				assert.Contains(t, textContent.Text, tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedComment github.IssueComment
			err = json.Unmarshal([]byte(textContent.Text), &returnedComment)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedComment.ID, *returnedComment.ID)
			assert.Equal(t, *tc.expectedComment.Body, *returnedComment.Body)
			assert.Equal(t, *tc.expectedComment.User.Login, *returnedComment.User.Login)

		})
	}
}

func Test_SearchIssues(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := SearchIssues(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "search_issues", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "q")
	assert.Contains(t, tool.InputSchema.Properties, "sort")
	assert.Contains(t, tool.InputSchema.Properties, "order")
	assert.Contains(t, tool.InputSchema.Properties, "perPage")
	assert.Contains(t, tool.InputSchema.Properties, "page")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"q"})

	// Setup mock search results
	mockSearchResult := &github.IssuesSearchResult{
		Total:             github.Ptr(2),
		IncompleteResults: github.Ptr(false),
		Issues: []*github.Issue{
			{
				Number:   github.Ptr(42),
				Title:    github.Ptr("Bug: Something is broken"),
				Body:     github.Ptr("This is a bug report"),
				State:    github.Ptr("open"),
				HTMLURL:  github.Ptr("https://github.com/owner/repo/issues/42"),
				Comments: github.Ptr(5),
				User: &github.User{
					Login: github.Ptr("user1"),
				},
			},
			{
				Number:   github.Ptr(43),
				Title:    github.Ptr("Feature: Add new functionality"),
				Body:     github.Ptr("This is a feature request"),
				State:    github.Ptr("open"),
				HTMLURL:  github.Ptr("https://github.com/owner/repo/issues/43"),
				Comments: github.Ptr(3),
				User: &github.User{
					Login: github.Ptr("user2"),
				},
			},
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedResult *github.IssuesSearchResult
		expectedErrMsg string
	}{
		{
			name: "successful issues search with all parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchIssues,
					expectQueryParams(
						t,
						map[string]string{
							"q":        "repo:owner/repo is:issue is:open",
							"sort":     "created",
							"order":    "desc",
							"page":     "1",
							"per_page": "30",
						},
					).andThen(
						mockResponse(t, http.StatusOK, mockSearchResult),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"q":       "repo:owner/repo is:issue is:open",
				"sort":    "created",
				"order":   "desc",
				"page":    float64(1),
				"perPage": float64(30),
			},
			expectError:    false,
			expectedResult: mockSearchResult,
		},
		{
			name: "issues search with minimal parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetSearchIssues,
					mockSearchResult,
				),
			),
			requestArgs: map[string]interface{}{
				"q": "repo:owner/repo is:issue is:open",
			},
			expectError:    false,
			expectedResult: mockSearchResult,
		},
		{
			name: "search issues fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchIssues,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"message": "Validation Failed"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"q": "invalid:query",
			},
			expectError:    true,
			expectedErrMsg: "failed to search issues",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := SearchIssues(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedResult github.IssuesSearchResult
			err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedResult.Total, *returnedResult.Total)
			assert.Equal(t, *tc.expectedResult.IncompleteResults, *returnedResult.IncompleteResults)
			assert.Len(t, returnedResult.Issues, len(tc.expectedResult.Issues))
			for i, issue := range returnedResult.Issues {
				assert.Equal(t, *tc.expectedResult.Issues[i].Number, *issue.Number)
				assert.Equal(t, *tc.expectedResult.Issues[i].Title, *issue.Title)
				assert.Equal(t, *tc.expectedResult.Issues[i].State, *issue.State)
				assert.Equal(t, *tc.expectedResult.Issues[i].HTMLURL, *issue.HTMLURL)
				assert.Equal(t, *tc.expectedResult.Issues[i].User.Login, *issue.User.Login)
			}
		})
	}
}

func Test_CreateIssue(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := CreateIssue(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "create_issue", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "title")
	assert.Contains(t, tool.InputSchema.Properties, "body")
	assert.Contains(t, tool.InputSchema.Properties, "assignees")
	assert.Contains(t, tool.InputSchema.Properties, "labels")
	assert.Contains(t, tool.InputSchema.Properties, "milestone")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "title"})

	// Setup mock issue for success case
	mockIssue := &github.Issue{
		Number:    github.Ptr(123),
		Title:     github.Ptr("Test Issue"),
		Body:      github.Ptr("This is a test issue"),
		State:     github.Ptr("open"),
		HTMLURL:   github.Ptr("https://github.com/owner/repo/issues/123"),
		Assignees: []*github.User{{Login: github.Ptr("user1")}, {Login: github.Ptr("user2")}},
		Labels:    []*github.Label{{Name: github.Ptr("bug")}, {Name: github.Ptr("help wanted")}},
		Milestone: &github.Milestone{Number: github.Ptr(5)},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedIssue  *github.Issue
		expectedErrMsg string
	}{
		{
			name: "successful issue creation with all fields",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposIssuesByOwnerByRepo,
					expectRequestBody(t, map[string]any{
						"title":     "Test Issue",
						"body":      "This is a test issue",
						"labels":    []any{"bug", "help wanted"},
						"assignees": []any{"user1", "user2"},
						"milestone": float64(5),
					}).andThen(
						mockResponse(t, http.StatusCreated, mockIssue),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":     "owner",
				"repo":      "repo",
				"title":     "Test Issue",
				"body":      "This is a test issue",
				"assignees": []any{"user1", "user2"},
				"labels":    []any{"bug", "help wanted"},
				"milestone": float64(5),
			},
			expectError:   false,
			expectedIssue: mockIssue,
		},
		{
			name: "successful issue creation with minimal fields",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposIssuesByOwnerByRepo,
					mockResponse(t, http.StatusCreated, &github.Issue{
						Number:  github.Ptr(124),
						Title:   github.Ptr("Minimal Issue"),
						HTMLURL: github.Ptr("https://github.com/owner/repo/issues/124"),
						State:   github.Ptr("open"),
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":     "owner",
				"repo":      "repo",
				"title":     "Minimal Issue",
				"assignees": nil, // Expect no failure with nil optional value.
			},
			expectError: false,
			expectedIssue: &github.Issue{
				Number:  github.Ptr(124),
				Title:   github.Ptr("Minimal Issue"),
				HTMLURL: github.Ptr("https://github.com/owner/repo/issues/124"),
				State:   github.Ptr("open"),
			},
		},
		{
			name: "issue creation fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposIssuesByOwnerByRepo,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message": "Validation failed"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
				"title": "",
			},
			expectError:    false,
			expectedErrMsg: "missing required parameter: title",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := CreateIssue(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			if tc.expectedErrMsg != "" {
				require.NotNil(t, result)
				textContent := getTextResult(t, result)
				assert.Contains(t, textContent.Text, tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedIssue github.Issue
			err = json.Unmarshal([]byte(textContent.Text), &returnedIssue)
			require.NoError(t, err)

			assert.Equal(t, *tc.expectedIssue.Number, *returnedIssue.Number)
			assert.Equal(t, *tc.expectedIssue.Title, *returnedIssue.Title)
			assert.Equal(t, *tc.expectedIssue.State, *returnedIssue.State)
			assert.Equal(t, *tc.expectedIssue.HTMLURL, *returnedIssue.HTMLURL)

			if tc.expectedIssue.Body != nil {
				assert.Equal(t, *tc.expectedIssue.Body, *returnedIssue.Body)
			}

			// Check assignees if expected
			if len(tc.expectedIssue.Assignees) > 0 {
				assert.Equal(t, len(tc.expectedIssue.Assignees), len(returnedIssue.Assignees))
				for i, assignee := range returnedIssue.Assignees {
					assert.Equal(t, *tc.expectedIssue.Assignees[i].Login, *assignee.Login)
				}
			}

			// Check labels if expected
			if len(tc.expectedIssue.Labels) > 0 {
				assert.Equal(t, len(tc.expectedIssue.Labels), len(returnedIssue.Labels))
				for i, label := range returnedIssue.Labels {
					assert.Equal(t, *tc.expectedIssue.Labels[i].Name, *label.Name)
				}
			}
		})
	}
}

func Test_ListIssues(t *testing.T) {
	// Verify tool definition
	mockClient := github.NewClient(nil)
	tool, _ := ListIssues(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "list_issues", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "state")
	assert.Contains(t, tool.InputSchema.Properties, "labels")
	assert.Contains(t, tool.InputSchema.Properties, "sort")
	assert.Contains(t, tool.InputSchema.Properties, "direction")
	assert.Contains(t, tool.InputSchema.Properties, "since")
	assert.Contains(t, tool.InputSchema.Properties, "page")
	assert.Contains(t, tool.InputSchema.Properties, "perPage")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo"})

	// Setup mock issues for success case
	mockIssues := []*github.Issue{
		{
			Number:    github.Ptr(123),
			Title:     github.Ptr("First Issue"),
			Body:      github.Ptr("This is the first test issue"),
			State:     github.Ptr("open"),
			HTMLURL:   github.Ptr("https://github.com/owner/repo/issues/123"),
			CreatedAt: &github.Timestamp{Time: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)},
		},
		{
			Number:    github.Ptr(456),
			Title:     github.Ptr("Second Issue"),
			Body:      github.Ptr("This is the second test issue"),
			State:     github.Ptr("open"),
			HTMLURL:   github.Ptr("https://github.com/owner/repo/issues/456"),
			Labels:    []*github.Label{{Name: github.Ptr("bug")}},
			CreatedAt: &github.Timestamp{Time: time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)},
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedIssues []*github.Issue
		expectedErrMsg string
	}{
		{
			name: "list issues with minimal parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposIssuesByOwnerByRepo,
					mockIssues,
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
			},
			expectError:    false,
			expectedIssues: mockIssues,
		},
		{
			name: "list issues with all parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposIssuesByOwnerByRepo,
					expectQueryParams(t, map[string]string{
						"state":     "open",
						"labels":    "bug,enhancement",
						"sort":      "created",
						"direction": "desc",
						"since":     "2023-01-01T00:00:00Z",
						"page":      "1",
						"per_page":  "30",
					}).andThen(
						mockResponse(t, http.StatusOK, mockIssues),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":     "owner",
				"repo":      "repo",
				"state":     "open",
				"labels":    []any{"bug", "enhancement"},
				"sort":      "created",
				"direction": "desc",
				"since":     "2023-01-01T00:00:00Z",
				"page":      float64(1),
				"perPage":   float64(30),
			},
			expectError:    false,
			expectedIssues: mockIssues,
		},
		{
			name: "invalid since parameter",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposIssuesByOwnerByRepo,
					mockIssues,
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
				"since": "invalid-date",
			},
			expectError:    true,
			expectedErrMsg: "invalid ISO 8601 timestamp",
		},
		{
			name: "list issues fails with error",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposIssuesByOwnerByRepo,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Repository not found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "nonexistent",
				"repo":  "repo",
			},
			expectError:    true,
			expectedErrMsg: "failed to list issues",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := ListIssues(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				if err != nil {
					assert.Contains(t, err.Error(), tc.expectedErrMsg)
				} else {
					// For errors returned as part of the result, not as an error
					assert.NotNil(t, result)
					textContent := getTextResult(t, result)
					assert.Contains(t, textContent.Text, tc.expectedErrMsg)
				}
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedIssues []*github.Issue
			err = json.Unmarshal([]byte(textContent.Text), &returnedIssues)
			require.NoError(t, err)

			assert.Len(t, returnedIssues, len(tc.expectedIssues))
			for i, issue := range returnedIssues {
				assert.Equal(t, *tc.expectedIssues[i].Number, *issue.Number)
				assert.Equal(t, *tc.expectedIssues[i].Title, *issue.Title)
				assert.Equal(t, *tc.expectedIssues[i].State, *issue.State)
				assert.Equal(t, *tc.expectedIssues[i].HTMLURL, *issue.HTMLURL)
			}
		})
	}
}

func Test_UpdateIssue(t *testing.T) {
	// Verify tool definition
	mockClient := github.NewClient(nil)
	tool, _ := UpdateIssue(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "update_issue", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "issue_number")
	assert.Contains(t, tool.InputSchema.Properties, "title")
	assert.Contains(t, tool.InputSchema.Properties, "body")
	assert.Contains(t, tool.InputSchema.Properties, "state")
	assert.Contains(t, tool.InputSchema.Properties, "labels")
	assert.Contains(t, tool.InputSchema.Properties, "assignees")
	assert.Contains(t, tool.InputSchema.Properties, "milestone")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "issue_number"})

	// Setup mock issue for success case
	mockIssue := &github.Issue{
		Number:    github.Ptr(123),
		Title:     github.Ptr("Updated Issue Title"),
		Body:      github.Ptr("Updated issue description"),
		State:     github.Ptr("closed"),
		HTMLURL:   github.Ptr("https://github.com/owner/repo/issues/123"),
		Assignees: []*github.User{{Login: github.Ptr("assignee1")}, {Login: github.Ptr("assignee2")}},
		Labels:    []*github.Label{{Name: github.Ptr("bug")}, {Name: github.Ptr("priority")}},
		Milestone: &github.Milestone{Number: github.Ptr(5)},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedIssue  *github.Issue
		expectedErrMsg string
	}{
		{
			name: "update issue with all fields",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PatchReposIssuesByOwnerByRepoByIssueNumber,
					expectRequestBody(t, map[string]any{
						"title":     "Updated Issue Title",
						"body":      "Updated issue description",
						"state":     "closed",
						"labels":    []any{"bug", "priority"},
						"assignees": []any{"assignee1", "assignee2"},
						"milestone": float64(5),
					}).andThen(
						mockResponse(t, http.StatusOK, mockIssue),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(123),
				"title":        "Updated Issue Title",
				"body":         "Updated issue description",
				"state":        "closed",
				"labels":       []any{"bug", "priority"},
				"assignees":    []any{"assignee1", "assignee2"},
				"milestone":    float64(5),
			},
			expectError:   false,
			expectedIssue: mockIssue,
		},
		{
			name: "update issue with minimal fields",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PatchReposIssuesByOwnerByRepoByIssueNumber,
					mockResponse(t, http.StatusOK, &github.Issue{
						Number:  github.Ptr(123),
						Title:   github.Ptr("Only Title Updated"),
						HTMLURL: github.Ptr("https://github.com/owner/repo/issues/123"),
						State:   github.Ptr("open"),
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(123),
				"title":        "Only Title Updated",
			},
			expectError: false,
			expectedIssue: &github.Issue{
				Number:  github.Ptr(123),
				Title:   github.Ptr("Only Title Updated"),
				HTMLURL: github.Ptr("https://github.com/owner/repo/issues/123"),
				State:   github.Ptr("open"),
			},
		},
		{
			name: "update issue fails with not found",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PatchReposIssuesByOwnerByRepoByIssueNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Issue not found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(999),
				"title":        "This issue doesn't exist",
			},
			expectError:    true,
			expectedErrMsg: "failed to update issue",
		},
		{
			name: "update issue fails with validation error",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PatchReposIssuesByOwnerByRepoByIssueNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message": "Invalid state value"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(123),
				"state":        "invalid_state",
			},
			expectError:    true,
			expectedErrMsg: "failed to update issue",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := UpdateIssue(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				if err != nil {
					assert.Contains(t, err.Error(), tc.expectedErrMsg)
				} else {
					// For errors returned as part of the result, not as an error
					require.NotNil(t, result)
					textContent := getTextResult(t, result)
					assert.Contains(t, textContent.Text, tc.expectedErrMsg)
				}
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedIssue github.Issue
			err = json.Unmarshal([]byte(textContent.Text), &returnedIssue)
			require.NoError(t, err)

			assert.Equal(t, *tc.expectedIssue.Number, *returnedIssue.Number)
			assert.Equal(t, *tc.expectedIssue.Title, *returnedIssue.Title)
			assert.Equal(t, *tc.expectedIssue.State, *returnedIssue.State)
			assert.Equal(t, *tc.expectedIssue.HTMLURL, *returnedIssue.HTMLURL)

			if tc.expectedIssue.Body != nil {
				assert.Equal(t, *tc.expectedIssue.Body, *returnedIssue.Body)
			}

			// Check assignees if expected
			if len(tc.expectedIssue.Assignees) > 0 {
				assert.Len(t, returnedIssue.Assignees, len(tc.expectedIssue.Assignees))
				for i, assignee := range returnedIssue.Assignees {
					assert.Equal(t, *tc.expectedIssue.Assignees[i].Login, *assignee.Login)
				}
			}

			// Check labels if expected
			if len(tc.expectedIssue.Labels) > 0 {
				assert.Len(t, returnedIssue.Labels, len(tc.expectedIssue.Labels))
				for i, label := range returnedIssue.Labels {
					assert.Equal(t, *tc.expectedIssue.Labels[i].Name, *label.Name)
				}
			}

			// Check milestone if expected
			if tc.expectedIssue.Milestone != nil {
				assert.NotNil(t, returnedIssue.Milestone)
				assert.Equal(t, *tc.expectedIssue.Milestone.Number, *returnedIssue.Milestone.Number)
			}
		})
	}
}

func Test_ParseISOTimestamp(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedErr  bool
		expectedTime time.Time
	}{
		{
			name:         "valid RFC3339 format",
			input:        "2023-01-15T14:30:00Z",
			expectedErr:  false,
			expectedTime: time.Date(2023, 1, 15, 14, 30, 0, 0, time.UTC),
		},
		{
			name:         "valid date only format",
			input:        "2023-01-15",
			expectedErr:  false,
			expectedTime: time.Date(2023, 1, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			name:        "empty timestamp",
			input:       "",
			expectedErr: true,
		},
		{
			name:        "invalid format",
			input:       "15/01/2023",
			expectedErr: true,
		},
		{
			name:        "invalid date",
			input:       "2023-13-45",
			expectedErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsedTime, err := parseISOTimestamp(tc.input)

			if tc.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedTime, parsedTime)
			}
		})
	}
}

func Test_GetIssueComments(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := GetIssueComments(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_issue_comments", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "issue_number")
	assert.Contains(t, tool.InputSchema.Properties, "page")
	assert.Contains(t, tool.InputSchema.Properties, "per_page")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "issue_number"})

	// Setup mock comments for success case
	mockComments := []*github.IssueComment{
		{
			ID:   github.Ptr(int64(123)),
			Body: github.Ptr("This is the first comment"),
			User: &github.User{
				Login: github.Ptr("user1"),
			},
			CreatedAt: &github.Timestamp{Time: time.Now().Add(-time.Hour * 24)},
		},
		{
			ID:   github.Ptr(int64(456)),
			Body: github.Ptr("This is the second comment"),
			User: &github.User{
				Login: github.Ptr("user2"),
			},
			CreatedAt: &github.Timestamp{Time: time.Now().Add(-time.Hour)},
		},
	}

	tests := []struct {
		name             string
		mockedClient     *http.Client
		requestArgs      map[string]interface{}
		expectError      bool
		expectedComments []*github.IssueComment
		expectedErrMsg   string
	}{
		{
			name: "successful comments retrieval",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposIssuesCommentsByOwnerByRepoByIssueNumber,
					mockComments,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(42),
			},
			expectError:      false,
			expectedComments: mockComments,
		},
		{
			name: "successful comments retrieval with pagination",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposIssuesCommentsByOwnerByRepoByIssueNumber,
					expectQueryParams(t, map[string]string{
						"page":     "2",
						"per_page": "10",
					}).andThen(
						mockResponse(t, http.StatusOK, mockComments),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(42),
				"page":         float64(2),
				"per_page":     float64(10),
			},
			expectError:      false,
			expectedComments: mockComments,
		},
		{
			name: "issue not found",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposIssuesCommentsByOwnerByRepoByIssueNumber,
					mockResponse(t, http.StatusNotFound, `{"message": "Issue not found"}`),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(999),
			},
			expectError:    true,
			expectedErrMsg: "failed to get issue comments",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetIssueComments(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedComments []*github.IssueComment
			err = json.Unmarshal([]byte(textContent.Text), &returnedComments)
			require.NoError(t, err)
			assert.Equal(t, len(tc.expectedComments), len(returnedComments))
			if len(returnedComments) > 0 {
				assert.Equal(t, *tc.expectedComments[0].Body, *returnedComments[0].Body)
				assert.Equal(t, *tc.expectedComments[0].User.Login, *returnedComments[0].User.Login)
			}
		})
	}
}
```

---

## `pkg/github/pullrequests.go`

```go
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// GetPullRequest creates a tool to get details of a specific pull request.
func GetPullRequest(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_pull_request",
			mcp.WithDescription(t("TOOL_GET_PULL_REQUEST_DESCRIPTION", "Get details of a specific pull request")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("pullNumber",
				mcp.Required(),
				mcp.Description("Pull request number"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pullNumber, err := RequiredInt(request, "pullNumber")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			pr, resp, err := client.PullRequests.Get(ctx, owner, repo, pullNumber)
			if err != nil {
				return nil, fmt.Errorf("failed to get pull request: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get pull request: %s", string(body))), nil
			}

			r, err := json.Marshal(pr)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// UpdatePullRequest creates a tool to update an existing pull request.
func UpdatePullRequest(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("update_pull_request",
			mcp.WithDescription(t("TOOL_UPDATE_PULL_REQUEST_DESCRIPTION", "Update an existing pull request in a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("pullNumber",
				mcp.Required(),
				mcp.Description("Pull request number to update"),
			),
			mcp.WithString("title",
				mcp.Description("New title"),
			),
			mcp.WithString("body",
				mcp.Description("New description"),
			),
			mcp.WithString("state",
				mcp.Description("New state ('open' or 'closed')"),
				mcp.Enum("open", "closed"),
			),
			mcp.WithString("base",
				mcp.Description("New base branch name"),
			),
			mcp.WithBoolean("maintainer_can_modify",
				mcp.Description("Allow maintainer edits"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pullNumber, err := RequiredInt(request, "pullNumber")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Build the update struct only with provided fields
			update := &github.PullRequest{}
			updateNeeded := false

			if title, ok, err := OptionalParamOK[string](request, "title"); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			} else if ok {
				update.Title = github.Ptr(title)
				updateNeeded = true
			}

			if body, ok, err := OptionalParamOK[string](request, "body"); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			} else if ok {
				update.Body = github.Ptr(body)
				updateNeeded = true
			}

			if state, ok, err := OptionalParamOK[string](request, "state"); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			} else if ok {
				update.State = github.Ptr(state)
				updateNeeded = true
			}

			if base, ok, err := OptionalParamOK[string](request, "base"); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			} else if ok {
				update.Base = &github.PullRequestBranch{Ref: github.Ptr(base)}
				updateNeeded = true
			}

			if maintainerCanModify, ok, err := OptionalParamOK[bool](request, "maintainer_can_modify"); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			} else if ok {
				update.MaintainerCanModify = github.Ptr(maintainerCanModify)
				updateNeeded = true
			}

			if !updateNeeded {
				return mcp.NewToolResultError("No update parameters provided."), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			pr, resp, err := client.PullRequests.Edit(ctx, owner, repo, pullNumber, update)
			if err != nil {
				return nil, fmt.Errorf("failed to update pull request: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to update pull request: %s", string(body))), nil
			}

			r, err := json.Marshal(pr)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// ListPullRequests creates a tool to list and filter repository pull requests.
func ListPullRequests(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("list_pull_requests",
			mcp.WithDescription(t("TOOL_LIST_PULL_REQUESTS_DESCRIPTION", "List and filter repository pull requests")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("state",
				mcp.Description("Filter by state ('open', 'closed', 'all')"),
			),
			mcp.WithString("head",
				mcp.Description("Filter by head user/org and branch"),
			),
			mcp.WithString("base",
				mcp.Description("Filter by base branch"),
			),
			mcp.WithString("sort",
				mcp.Description("Sort by ('created', 'updated', 'popularity', 'long-running')"),
			),
			mcp.WithString("direction",
				mcp.Description("Sort direction ('asc', 'desc')"),
			),
			WithPagination(),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			state, err := OptionalParam[string](request, "state")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			head, err := OptionalParam[string](request, "head")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			base, err := OptionalParam[string](request, "base")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			sort, err := OptionalParam[string](request, "sort")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			direction, err := OptionalParam[string](request, "direction")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pagination, err := OptionalPaginationParams(request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.PullRequestListOptions{
				State:     state,
				Head:      head,
				Base:      base,
				Sort:      sort,
				Direction: direction,
				ListOptions: github.ListOptions{
					PerPage: pagination.perPage,
					Page:    pagination.page,
				},
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			prs, resp, err := client.PullRequests.List(ctx, owner, repo, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to list pull requests: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to list pull requests: %s", string(body))), nil
			}

			r, err := json.Marshal(prs)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// MergePullRequest creates a tool to merge a pull request.
func MergePullRequest(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("merge_pull_request",
			mcp.WithDescription(t("TOOL_MERGE_PULL_REQUEST_DESCRIPTION", "Merge a pull request")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("pullNumber",
				mcp.Required(),
				mcp.Description("Pull request number"),
			),
			mcp.WithString("commit_title",
				mcp.Description("Title for merge commit"),
			),
			mcp.WithString("commit_message",
				mcp.Description("Extra detail for merge commit"),
			),
			mcp.WithString("merge_method",
				mcp.Description("Merge method ('merge', 'squash', 'rebase')"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pullNumber, err := RequiredInt(request, "pullNumber")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			commitTitle, err := OptionalParam[string](request, "commit_title")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			commitMessage, err := OptionalParam[string](request, "commit_message")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			mergeMethod, err := OptionalParam[string](request, "merge_method")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			options := &github.PullRequestOptions{
				CommitTitle: commitTitle,
				MergeMethod: mergeMethod,
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			result, resp, err := client.PullRequests.Merge(ctx, owner, repo, pullNumber, commitMessage, options)
			if err != nil {
				return nil, fmt.Errorf("failed to merge pull request: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to merge pull request: %s", string(body))), nil
			}

			r, err := json.Marshal(result)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// GetPullRequestFiles creates a tool to get the list of files changed in a pull request.
func GetPullRequestFiles(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_pull_request_files",
			mcp.WithDescription(t("TOOL_GET_PULL_REQUEST_FILES_DESCRIPTION", "Get the list of files changed in a pull request")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("pullNumber",
				mcp.Required(),
				mcp.Description("Pull request number"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pullNumber, err := RequiredInt(request, "pullNumber")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			opts := &github.ListOptions{}
			files, resp, err := client.PullRequests.ListFiles(ctx, owner, repo, pullNumber, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to get pull request files: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get pull request files: %s", string(body))), nil
			}

			r, err := json.Marshal(files)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// GetPullRequestStatus creates a tool to get the combined status of all status checks for a pull request.
func GetPullRequestStatus(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_pull_request_status",
			mcp.WithDescription(t("TOOL_GET_PULL_REQUEST_STATUS_DESCRIPTION", "Get the combined status of all status checks for a pull request")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("pullNumber",
				mcp.Required(),
				mcp.Description("Pull request number"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pullNumber, err := RequiredInt(request, "pullNumber")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			// First get the PR to find the head SHA
			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			pr, resp, err := client.PullRequests.Get(ctx, owner, repo, pullNumber)
			if err != nil {
				return nil, fmt.Errorf("failed to get pull request: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get pull request: %s", string(body))), nil
			}

			// Get combined status for the head SHA
			status, resp, err := client.Repositories.GetCombinedStatus(ctx, owner, repo, *pr.Head.SHA, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get combined status: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get combined status: %s", string(body))), nil
			}

			r, err := json.Marshal(status)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// UpdatePullRequestBranch creates a tool to update a pull request branch with the latest changes from the base branch.
func UpdatePullRequestBranch(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("update_pull_request_branch",
			mcp.WithDescription(t("TOOL_UPDATE_PULL_REQUEST_BRANCH_DESCRIPTION", "Update a pull request branch with the latest changes from the base branch")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("pullNumber",
				mcp.Required(),
				mcp.Description("Pull request number"),
			),
			mcp.WithString("expectedHeadSha",
				mcp.Description("The expected SHA of the pull request's HEAD ref"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pullNumber, err := RequiredInt(request, "pullNumber")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			expectedHeadSHA, err := OptionalParam[string](request, "expectedHeadSha")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			opts := &github.PullRequestBranchUpdateOptions{}
			if expectedHeadSHA != "" {
				opts.ExpectedHeadSHA = github.Ptr(expectedHeadSHA)
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			result, resp, err := client.PullRequests.UpdateBranch(ctx, owner, repo, pullNumber, opts)
			if err != nil {
				// Check if it's an acceptedError. An acceptedError indicates that the update is in progress,
				// and it's not a real error.
				if resp != nil && resp.StatusCode == http.StatusAccepted && isAcceptedError(err) {
					return mcp.NewToolResultText("Pull request branch update is in progress"), nil
				}
				return nil, fmt.Errorf("failed to update pull request branch: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusAccepted {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to update pull request branch: %s", string(body))), nil
			}

			r, err := json.Marshal(result)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// GetPullRequestComments creates a tool to get the review comments on a pull request.
func GetPullRequestComments(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_pull_request_comments",
			mcp.WithDescription(t("TOOL_GET_PULL_REQUEST_COMMENTS_DESCRIPTION", "Get the review comments on a pull request")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("pullNumber",
				mcp.Required(),
				mcp.Description("Pull request number"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pullNumber, err := RequiredInt(request, "pullNumber")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.PullRequestListCommentsOptions{
				ListOptions: github.ListOptions{
					PerPage: 100,
				},
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			comments, resp, err := client.PullRequests.ListComments(ctx, owner, repo, pullNumber, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to get pull request comments: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get pull request comments: %s", string(body))), nil
			}

			r, err := json.Marshal(comments)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// AddPullRequestReviewComment creates a tool to add a review comment to a pull request.
func AddPullRequestReviewComment(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("add_pull_request_review_comment",
			mcp.WithDescription(t("TOOL_ADD_PULL_REQUEST_COMMENT_DESCRIPTION", "Add a review comment to a pull request")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("pull_number",
				mcp.Required(),
				mcp.Description("Pull request number"),
			),
			mcp.WithString("body",
				mcp.Required(),
				mcp.Description("The text of the review comment"),
			),
			mcp.WithString("commit_id",
				mcp.Description("The SHA of the commit to comment on. Required unless in_reply_to is specified."),
			),
			mcp.WithString("path",
				mcp.Description("The relative path to the file that necessitates a comment. Required unless in_reply_to is specified."),
			),
			mcp.WithString("subject_type",
				mcp.Description("The level at which the comment is targeted, 'line' or 'file'"),
				mcp.Enum("line", "file"),
			),
			mcp.WithNumber("line",
				mcp.Description("The line of the blob in the pull request diff that the comment applies to. For multi-line comments, the last line of the range"),
			),
			mcp.WithString("side",
				mcp.Description("The side of the diff to comment on. Can be LEFT or RIGHT"),
				mcp.Enum("LEFT", "RIGHT"),
			),
			mcp.WithNumber("start_line",
				mcp.Description("For multi-line comments, the first line of the range that the comment applies to"),
			),
			mcp.WithString("start_side",
				mcp.Description("For multi-line comments, the starting side of the diff that the comment applies to. Can be LEFT or RIGHT"),
				mcp.Enum("LEFT", "RIGHT"),
			),
			mcp.WithNumber("in_reply_to",
				mcp.Description("The ID of the review comment to reply to. When specified, only body is required and all other parameters are ignored"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pullNumber, err := RequiredInt(request, "pull_number")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			body, err := requiredParam[string](request, "body")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}

			// Check if this is a reply to an existing comment
			if replyToFloat, ok := request.Params.Arguments["in_reply_to"].(float64); ok {
				// Use the specialized method for reply comments due to inconsistency in underlying go-github library: https://github.com/google/go-github/pull/950
				commentID := int64(replyToFloat)
				createdReply, resp, err := client.PullRequests.CreateCommentInReplyTo(ctx, owner, repo, pullNumber, body, commentID)
				if err != nil {
					return nil, fmt.Errorf("failed to reply to pull request comment: %w", err)
				}
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusCreated {
					respBody, err := io.ReadAll(resp.Body)
					if err != nil {
						return nil, fmt.Errorf("failed to read response body: %w", err)
					}
					return mcp.NewToolResultError(fmt.Sprintf("failed to reply to pull request comment: %s", string(respBody))), nil
				}

				r, err := json.Marshal(createdReply)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal response: %w", err)
				}

				return mcp.NewToolResultText(string(r)), nil
			}

			// This is a new comment, not a reply
			// Verify required parameters for a new comment
			commitID, err := requiredParam[string](request, "commit_id")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			path, err := requiredParam[string](request, "path")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			comment := &github.PullRequestComment{
				Body:     github.Ptr(body),
				CommitID: github.Ptr(commitID),
				Path:     github.Ptr(path),
			}

			subjectType, err := OptionalParam[string](request, "subject_type")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if subjectType != "file" {
				line, lineExists := request.Params.Arguments["line"].(float64)
				startLine, startLineExists := request.Params.Arguments["start_line"].(float64)
				side, sideExists := request.Params.Arguments["side"].(string)
				startSide, startSideExists := request.Params.Arguments["start_side"].(string)

				if !lineExists {
					return mcp.NewToolResultError("line parameter is required unless using subject_type:file"), nil
				}

				comment.Line = github.Ptr(int(line))
				if sideExists {
					comment.Side = github.Ptr(side)
				}
				if startLineExists {
					comment.StartLine = github.Ptr(int(startLine))
				}
				if startSideExists {
					comment.StartSide = github.Ptr(startSide)
				}

				if startLineExists && !lineExists {
					return mcp.NewToolResultError("if start_line is provided, line must also be provided"), nil
				}
				if startSideExists && !sideExists {
					return mcp.NewToolResultError("if start_side is provided, side must also be provided"), nil
				}
			}

			createdComment, resp, err := client.PullRequests.CreateComment(ctx, owner, repo, pullNumber, comment)
			if err != nil {
				return nil, fmt.Errorf("failed to create pull request comment: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusCreated {
				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to create pull request comment: %s", string(respBody))), nil
			}

			r, err := json.Marshal(createdComment)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// GetPullRequestReviews creates a tool to get the reviews on a pull request.
func GetPullRequestReviews(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_pull_request_reviews",
			mcp.WithDescription(t("TOOL_GET_PULL_REQUEST_REVIEWS_DESCRIPTION", "Get the reviews on a pull request")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("pullNumber",
				mcp.Required(),
				mcp.Description("Pull request number"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pullNumber, err := RequiredInt(request, "pullNumber")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			reviews, resp, err := client.PullRequests.ListReviews(ctx, owner, repo, pullNumber, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get pull request reviews: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get pull request reviews: %s", string(body))), nil
			}

			r, err := json.Marshal(reviews)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// CreatePullRequestReview creates a tool to submit a review on a pull request.
func CreatePullRequestReview(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("create_pull_request_review",
			mcp.WithDescription(t("TOOL_CREATE_PULL_REQUEST_REVIEW_DESCRIPTION", "Create a review on a pull request")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithNumber("pullNumber",
				mcp.Required(),
				mcp.Description("Pull request number"),
			),
			mcp.WithString("body",
				mcp.Description("Review comment text"),
			),
			mcp.WithString("event",
				mcp.Required(),
				mcp.Description("Review action ('APPROVE', 'REQUEST_CHANGES', 'COMMENT')"),
			),
			mcp.WithString("commitId",
				mcp.Description("SHA of commit to review"),
			),
			mcp.WithArray("comments",
				mcp.Items(
					map[string]interface{}{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"path", "body"},
						"properties": map[string]interface{}{
							"path": map[string]interface{}{
								"type":        "string",
								"description": "path to the file",
							},
							"position": map[string]interface{}{
								"type":        "number",
								"description": "position of the comment in the diff",
							},
							"line": map[string]interface{}{
								"type":        "number",
								"description": "line number in the file to comment on. For multi-line comments, the end of the line range",
							},
							"side": map[string]interface{}{
								"type":        "string",
								"description": "The side of the diff on which the line resides. For multi-line comments, this is the side for the end of the line range. (LEFT or RIGHT)",
							},
							"start_line": map[string]interface{}{
								"type":        "number",
								"description": "The first line of the range to which the comment refers. Required for multi-line comments.",
							},
							"start_side": map[string]interface{}{
								"type":        "string",
								"description": "The side of the diff on which the start line resides for multi-line comments. (LEFT or RIGHT)",
							},
							"body": map[string]interface{}{
								"type":        "string",
								"description": "comment body",
							},
						},
					},
				),
				mcp.Description("Line-specific comments array of objects to place comments on pull request changes. Requires path and body. For line comments use line or position. For multi-line comments use start_line and line with optional side parameters."),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pullNumber, err := RequiredInt(request, "pullNumber")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			event, err := requiredParam[string](request, "event")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Create review request
			reviewRequest := &github.PullRequestReviewRequest{
				Event: github.Ptr(event),
			}

			// Add body if provided
			body, err := OptionalParam[string](request, "body")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if body != "" {
				reviewRequest.Body = github.Ptr(body)
			}

			// Add commit ID if provided
			commitID, err := OptionalParam[string](request, "commitId")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if commitID != "" {
				reviewRequest.CommitID = github.Ptr(commitID)
			}

			// Add comments if provided
			if commentsObj, ok := request.Params.Arguments["comments"].([]interface{}); ok && len(commentsObj) > 0 {
				comments := []*github.DraftReviewComment{}

				for _, c := range commentsObj {
					commentMap, ok := c.(map[string]interface{})
					if !ok {
						return mcp.NewToolResultError("each comment must be an object with path and body"), nil
					}

					path, ok := commentMap["path"].(string)
					if !ok || path == "" {
						return mcp.NewToolResultError("each comment must have a path"), nil
					}

					body, ok := commentMap["body"].(string)
					if !ok || body == "" {
						return mcp.NewToolResultError("each comment must have a body"), nil
					}

					_, hasPosition := commentMap["position"].(float64)
					_, hasLine := commentMap["line"].(float64)
					_, hasSide := commentMap["side"].(string)
					_, hasStartLine := commentMap["start_line"].(float64)
					_, hasStartSide := commentMap["start_side"].(string)

					switch {
					case !hasPosition && !hasLine:
						return mcp.NewToolResultError("each comment must have either position or line"), nil
					case hasPosition && (hasLine || hasSide || hasStartLine || hasStartSide):
						return mcp.NewToolResultError("position cannot be combined with line, side, start_line, or start_side"), nil
					case hasStartSide && !hasSide:
						return mcp.NewToolResultError("if start_side is provided, side must also be provided"), nil
					}

					comment := &github.DraftReviewComment{
						Path: github.Ptr(path),
						Body: github.Ptr(body),
					}

					if positionFloat, ok := commentMap["position"].(float64); ok {
						comment.Position = github.Ptr(int(positionFloat))
					} else if lineFloat, ok := commentMap["line"].(float64); ok {
						comment.Line = github.Ptr(int(lineFloat))
					}
					if side, ok := commentMap["side"].(string); ok {
						comment.Side = github.Ptr(side)
					}
					if startLineFloat, ok := commentMap["start_line"].(float64); ok {
						comment.StartLine = github.Ptr(int(startLineFloat))
					}
					if startSide, ok := commentMap["start_side"].(string); ok {
						comment.StartSide = github.Ptr(startSide)
					}

					comments = append(comments, comment)
				}

				reviewRequest.Comments = comments
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			review, resp, err := client.PullRequests.CreateReview(ctx, owner, repo, pullNumber, reviewRequest)
			if err != nil {
				return nil, fmt.Errorf("failed to create pull request review: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to create pull request review: %s", string(body))), nil
			}

			r, err := json.Marshal(review)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// CreatePullRequest creates a tool to create a new pull request.
func CreatePullRequest(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("create_pull_request",
			mcp.WithDescription(t("TOOL_CREATE_PULL_REQUEST_DESCRIPTION", "Create a new pull request in a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("title",
				mcp.Required(),
				mcp.Description("PR title"),
			),
			mcp.WithString("body",
				mcp.Description("PR description"),
			),
			mcp.WithString("head",
				mcp.Required(),
				mcp.Description("Branch containing changes"),
			),
			mcp.WithString("base",
				mcp.Required(),
				mcp.Description("Branch to merge into"),
			),
			mcp.WithBoolean("draft",
				mcp.Description("Create as draft PR"),
			),
			mcp.WithBoolean("maintainer_can_modify",
				mcp.Description("Allow maintainer edits"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			title, err := requiredParam[string](request, "title")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			head, err := requiredParam[string](request, "head")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			base, err := requiredParam[string](request, "base")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			body, err := OptionalParam[string](request, "body")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			draft, err := OptionalParam[bool](request, "draft")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			maintainerCanModify, err := OptionalParam[bool](request, "maintainer_can_modify")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			newPR := &github.NewPullRequest{
				Title: github.Ptr(title),
				Head:  github.Ptr(head),
				Base:  github.Ptr(base),
			}

			if body != "" {
				newPR.Body = github.Ptr(body)
			}

			newPR.Draft = github.Ptr(draft)
			newPR.MaintainerCanModify = github.Ptr(maintainerCanModify)

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			pr, resp, err := client.PullRequests.Create(ctx, owner, repo, newPR)
			if err != nil {
				return nil, fmt.Errorf("failed to create pull request: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusCreated {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to create pull request: %s", string(body))), nil
			}

			r, err := json.Marshal(pr)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}
```

---

## `pkg/github/pullrequests_test.go`

```go
package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetPullRequest(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := GetPullRequest(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_pull_request", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "pullNumber")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "pullNumber"})

	// Setup mock PR for success case
	mockPR := &github.PullRequest{
		Number:  github.Ptr(42),
		Title:   github.Ptr("Test PR"),
		State:   github.Ptr("open"),
		HTMLURL: github.Ptr("https://github.com/owner/repo/pull/42"),
		Head: &github.PullRequestBranch{
			SHA: github.Ptr("abcd1234"),
			Ref: github.Ptr("feature-branch"),
		},
		Base: &github.PullRequestBranch{
			Ref: github.Ptr("main"),
		},
		Body: github.Ptr("This is a test PR"),
		User: &github.User{
			Login: github.Ptr("testuser"),
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedPR     *github.PullRequest
		expectedErrMsg string
	}{
		{
			name: "successful PR fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposPullsByOwnerByRepoByPullNumber,
					mockPR,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
			},
			expectError: false,
			expectedPR:  mockPR,
		},
		{
			name: "PR fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposPullsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(999),
			},
			expectError:    true,
			expectedErrMsg: "failed to get pull request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetPullRequest(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedPR github.PullRequest
			err = json.Unmarshal([]byte(textContent.Text), &returnedPR)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedPR.Number, *returnedPR.Number)
			assert.Equal(t, *tc.expectedPR.Title, *returnedPR.Title)
			assert.Equal(t, *tc.expectedPR.State, *returnedPR.State)
			assert.Equal(t, *tc.expectedPR.HTMLURL, *returnedPR.HTMLURL)
		})
	}
}

func Test_UpdatePullRequest(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := UpdatePullRequest(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "update_pull_request", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "pullNumber")
	assert.Contains(t, tool.InputSchema.Properties, "title")
	assert.Contains(t, tool.InputSchema.Properties, "body")
	assert.Contains(t, tool.InputSchema.Properties, "state")
	assert.Contains(t, tool.InputSchema.Properties, "base")
	assert.Contains(t, tool.InputSchema.Properties, "maintainer_can_modify")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "pullNumber"})

	// Setup mock PR for success case
	mockUpdatedPR := &github.PullRequest{
		Number:              github.Ptr(42),
		Title:               github.Ptr("Updated Test PR Title"),
		State:               github.Ptr("open"),
		HTMLURL:             github.Ptr("https://github.com/owner/repo/pull/42"),
		Body:                github.Ptr("Updated test PR body."),
		MaintainerCanModify: github.Ptr(false),
		Base: &github.PullRequestBranch{
			Ref: github.Ptr("develop"),
		},
	}

	mockClosedPR := &github.PullRequest{
		Number: github.Ptr(42),
		Title:  github.Ptr("Test PR"),
		State:  github.Ptr("closed"), // State updated
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedPR     *github.PullRequest
		expectedErrMsg string
	}{
		{
			name: "successful PR update (title, body, base, maintainer_can_modify)",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PatchReposPullsByOwnerByRepoByPullNumber,
					// Expect the flat string based on previous test failure output and API docs
					expectRequestBody(t, map[string]interface{}{
						"title":                 "Updated Test PR Title",
						"body":                  "Updated test PR body.",
						"base":                  "develop",
						"maintainer_can_modify": false,
					}).andThen(
						mockResponse(t, http.StatusOK, mockUpdatedPR),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":                 "owner",
				"repo":                  "repo",
				"pullNumber":            float64(42),
				"title":                 "Updated Test PR Title",
				"body":                  "Updated test PR body.",
				"base":                  "develop",
				"maintainer_can_modify": false,
			},
			expectError: false,
			expectedPR:  mockUpdatedPR,
		},
		{
			name: "successful PR update (state)",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PatchReposPullsByOwnerByRepoByPullNumber,
					expectRequestBody(t, map[string]interface{}{
						"state": "closed",
					}).andThen(
						mockResponse(t, http.StatusOK, mockClosedPR),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"state":      "closed",
			},
			expectError: false,
			expectedPR:  mockClosedPR,
		},
		{
			name:         "no update parameters provided",
			mockedClient: mock.NewMockedHTTPClient(), // No API call expected
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				// No update fields
			},
			expectError:    false, // Error is returned in the result, not as Go error
			expectedErrMsg: "No update parameters provided",
		},
		{
			name: "PR update fails (API error)",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PatchReposPullsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message": "Validation Failed"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"title":      "Invalid Title Causing Error",
			},
			expectError:    true,
			expectedErrMsg: "failed to update pull request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := UpdatePullRequest(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content
			textContent := getTextResult(t, result)

			// Check for expected error message within the result text
			if tc.expectedErrMsg != "" {
				assert.Contains(t, textContent.Text, tc.expectedErrMsg)
				return
			}

			// Unmarshal and verify the successful result
			var returnedPR github.PullRequest
			err = json.Unmarshal([]byte(textContent.Text), &returnedPR)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedPR.Number, *returnedPR.Number)
			if tc.expectedPR.Title != nil {
				assert.Equal(t, *tc.expectedPR.Title, *returnedPR.Title)
			}
			if tc.expectedPR.Body != nil {
				assert.Equal(t, *tc.expectedPR.Body, *returnedPR.Body)
			}
			if tc.expectedPR.State != nil {
				assert.Equal(t, *tc.expectedPR.State, *returnedPR.State)
			}
			if tc.expectedPR.Base != nil && tc.expectedPR.Base.Ref != nil {
				assert.NotNil(t, returnedPR.Base)
				assert.Equal(t, *tc.expectedPR.Base.Ref, *returnedPR.Base.Ref)
			}
			if tc.expectedPR.MaintainerCanModify != nil {
				assert.Equal(t, *tc.expectedPR.MaintainerCanModify, *returnedPR.MaintainerCanModify)
			}
		})
	}
}

func Test_ListPullRequests(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := ListPullRequests(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "list_pull_requests", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "state")
	assert.Contains(t, tool.InputSchema.Properties, "head")
	assert.Contains(t, tool.InputSchema.Properties, "base")
	assert.Contains(t, tool.InputSchema.Properties, "sort")
	assert.Contains(t, tool.InputSchema.Properties, "direction")
	assert.Contains(t, tool.InputSchema.Properties, "perPage")
	assert.Contains(t, tool.InputSchema.Properties, "page")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo"})

	// Setup mock PRs for success case
	mockPRs := []*github.PullRequest{
		{
			Number:  github.Ptr(42),
			Title:   github.Ptr("First PR"),
			State:   github.Ptr("open"),
			HTMLURL: github.Ptr("https://github.com/owner/repo/pull/42"),
		},
		{
			Number:  github.Ptr(43),
			Title:   github.Ptr("Second PR"),
			State:   github.Ptr("closed"),
			HTMLURL: github.Ptr("https://github.com/owner/repo/pull/43"),
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedPRs    []*github.PullRequest
		expectedErrMsg string
	}{
		{
			name: "successful PRs listing",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposPullsByOwnerByRepo,
					expectQueryParams(t, map[string]string{
						"state":     "all",
						"sort":      "created",
						"direction": "desc",
						"per_page":  "30",
						"page":      "1",
					}).andThen(
						mockResponse(t, http.StatusOK, mockPRs),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":     "owner",
				"repo":      "repo",
				"state":     "all",
				"sort":      "created",
				"direction": "desc",
				"perPage":   float64(30),
				"page":      float64(1),
			},
			expectError: false,
			expectedPRs: mockPRs,
		},
		{
			name: "PRs listing fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposPullsByOwnerByRepo,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"message": "Invalid request"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
				"state": "invalid",
			},
			expectError:    true,
			expectedErrMsg: "failed to list pull requests",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := ListPullRequests(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedPRs []*github.PullRequest
			err = json.Unmarshal([]byte(textContent.Text), &returnedPRs)
			require.NoError(t, err)
			assert.Len(t, returnedPRs, 2)
			assert.Equal(t, *tc.expectedPRs[0].Number, *returnedPRs[0].Number)
			assert.Equal(t, *tc.expectedPRs[0].Title, *returnedPRs[0].Title)
			assert.Equal(t, *tc.expectedPRs[0].State, *returnedPRs[0].State)
			assert.Equal(t, *tc.expectedPRs[1].Number, *returnedPRs[1].Number)
			assert.Equal(t, *tc.expectedPRs[1].Title, *returnedPRs[1].Title)
			assert.Equal(t, *tc.expectedPRs[1].State, *returnedPRs[1].State)
		})
	}
}

func Test_MergePullRequest(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := MergePullRequest(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "merge_pull_request", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "pullNumber")
	assert.Contains(t, tool.InputSchema.Properties, "commit_title")
	assert.Contains(t, tool.InputSchema.Properties, "commit_message")
	assert.Contains(t, tool.InputSchema.Properties, "merge_method")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "pullNumber"})

	// Setup mock merge result for success case
	mockMergeResult := &github.PullRequestMergeResult{
		Merged:  github.Ptr(true),
		Message: github.Ptr("Pull Request successfully merged"),
		SHA:     github.Ptr("abcd1234efgh5678"),
	}

	tests := []struct {
		name                string
		mockedClient        *http.Client
		requestArgs         map[string]interface{}
		expectError         bool
		expectedMergeResult *github.PullRequestMergeResult
		expectedErrMsg      string
	}{
		{
			name: "successful merge",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PutReposPullsMergeByOwnerByRepoByPullNumber,
					expectRequestBody(t, map[string]interface{}{
						"commit_title":   "Merge PR #42",
						"commit_message": "Merging awesome feature",
						"merge_method":   "squash",
					}).andThen(
						mockResponse(t, http.StatusOK, mockMergeResult),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":          "owner",
				"repo":           "repo",
				"pullNumber":     float64(42),
				"commit_title":   "Merge PR #42",
				"commit_message": "Merging awesome feature",
				"merge_method":   "squash",
			},
			expectError:         false,
			expectedMergeResult: mockMergeResult,
		},
		{
			name: "merge fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PutReposPullsMergeByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusMethodNotAllowed)
						_, _ = w.Write([]byte(`{"message": "Pull request cannot be merged"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
			},
			expectError:    true,
			expectedErrMsg: "failed to merge pull request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := MergePullRequest(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedResult github.PullRequestMergeResult
			err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedMergeResult.Merged, *returnedResult.Merged)
			assert.Equal(t, *tc.expectedMergeResult.Message, *returnedResult.Message)
			assert.Equal(t, *tc.expectedMergeResult.SHA, *returnedResult.SHA)
		})
	}
}

func Test_GetPullRequestFiles(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := GetPullRequestFiles(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_pull_request_files", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "pullNumber")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "pullNumber"})

	// Setup mock PR files for success case
	mockFiles := []*github.CommitFile{
		{
			Filename:  github.Ptr("file1.go"),
			Status:    github.Ptr("modified"),
			Additions: github.Ptr(10),
			Deletions: github.Ptr(5),
			Changes:   github.Ptr(15),
			Patch:     github.Ptr("@@ -1,5 +1,10 @@"),
		},
		{
			Filename:  github.Ptr("file2.go"),
			Status:    github.Ptr("added"),
			Additions: github.Ptr(20),
			Deletions: github.Ptr(0),
			Changes:   github.Ptr(20),
			Patch:     github.Ptr("@@ -0,0 +1,20 @@"),
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedFiles  []*github.CommitFile
		expectedErrMsg string
	}{
		{
			name: "successful files fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposPullsFilesByOwnerByRepoByPullNumber,
					mockFiles,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
			},
			expectError:   false,
			expectedFiles: mockFiles,
		},
		{
			name: "files fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposPullsFilesByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(999),
			},
			expectError:    true,
			expectedErrMsg: "failed to get pull request files",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetPullRequestFiles(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedFiles []*github.CommitFile
			err = json.Unmarshal([]byte(textContent.Text), &returnedFiles)
			require.NoError(t, err)
			assert.Len(t, returnedFiles, len(tc.expectedFiles))
			for i, file := range returnedFiles {
				assert.Equal(t, *tc.expectedFiles[i].Filename, *file.Filename)
				assert.Equal(t, *tc.expectedFiles[i].Status, *file.Status)
				assert.Equal(t, *tc.expectedFiles[i].Additions, *file.Additions)
				assert.Equal(t, *tc.expectedFiles[i].Deletions, *file.Deletions)
			}
		})
	}
}

func Test_GetPullRequestStatus(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := GetPullRequestStatus(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_pull_request_status", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "pullNumber")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "pullNumber"})

	// Setup mock PR for successful PR fetch
	mockPR := &github.PullRequest{
		Number:  github.Ptr(42),
		Title:   github.Ptr("Test PR"),
		HTMLURL: github.Ptr("https://github.com/owner/repo/pull/42"),
		Head: &github.PullRequestBranch{
			SHA: github.Ptr("abcd1234"),
			Ref: github.Ptr("feature-branch"),
		},
	}

	// Setup mock status for success case
	mockStatus := &github.CombinedStatus{
		State:      github.Ptr("success"),
		TotalCount: github.Ptr(3),
		Statuses: []*github.RepoStatus{
			{
				State:       github.Ptr("success"),
				Context:     github.Ptr("continuous-integration/travis-ci"),
				Description: github.Ptr("Build succeeded"),
				TargetURL:   github.Ptr("https://travis-ci.org/owner/repo/builds/123"),
			},
			{
				State:       github.Ptr("success"),
				Context:     github.Ptr("codecov/patch"),
				Description: github.Ptr("Coverage increased"),
				TargetURL:   github.Ptr("https://codecov.io/gh/owner/repo/pull/42"),
			},
			{
				State:       github.Ptr("success"),
				Context:     github.Ptr("lint/golangci-lint"),
				Description: github.Ptr("No issues found"),
				TargetURL:   github.Ptr("https://golangci.com/r/owner/repo/pull/42"),
			},
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedStatus *github.CombinedStatus
		expectedErrMsg string
	}{
		{
			name: "successful status fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposPullsByOwnerByRepoByPullNumber,
					mockPR,
				),
				mock.WithRequestMatch(
					mock.GetReposCommitsStatusByOwnerByRepoByRef,
					mockStatus,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
			},
			expectError:    false,
			expectedStatus: mockStatus,
		},
		{
			name: "PR fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposPullsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(999),
			},
			expectError:    true,
			expectedErrMsg: "failed to get pull request",
		},
		{
			name: "status fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposPullsByOwnerByRepoByPullNumber,
					mockPR,
				),
				mock.WithRequestMatchHandler(
					mock.GetReposCommitsStatusesByOwnerByRepoByRef,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
			},
			expectError:    true,
			expectedErrMsg: "failed to get combined status",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetPullRequestStatus(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedStatus github.CombinedStatus
			err = json.Unmarshal([]byte(textContent.Text), &returnedStatus)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedStatus.State, *returnedStatus.State)
			assert.Equal(t, *tc.expectedStatus.TotalCount, *returnedStatus.TotalCount)
			assert.Len(t, returnedStatus.Statuses, len(tc.expectedStatus.Statuses))
			for i, status := range returnedStatus.Statuses {
				assert.Equal(t, *tc.expectedStatus.Statuses[i].State, *status.State)
				assert.Equal(t, *tc.expectedStatus.Statuses[i].Context, *status.Context)
				assert.Equal(t, *tc.expectedStatus.Statuses[i].Description, *status.Description)
			}
		})
	}
}

func Test_UpdatePullRequestBranch(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := UpdatePullRequestBranch(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "update_pull_request_branch", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "pullNumber")
	assert.Contains(t, tool.InputSchema.Properties, "expectedHeadSha")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "pullNumber"})

	// Setup mock update result for success case
	mockUpdateResult := &github.PullRequestBranchUpdateResponse{
		Message: github.Ptr("Branch was updated successfully"),
		URL:     github.Ptr("https://api.github.com/repos/owner/repo/pulls/42"),
	}

	tests := []struct {
		name                 string
		mockedClient         *http.Client
		requestArgs          map[string]interface{}
		expectError          bool
		expectedUpdateResult *github.PullRequestBranchUpdateResponse
		expectedErrMsg       string
	}{
		{
			name: "successful branch update",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PutReposPullsUpdateBranchByOwnerByRepoByPullNumber,
					expectRequestBody(t, map[string]interface{}{
						"expected_head_sha": "abcd1234",
					}).andThen(
						mockResponse(t, http.StatusAccepted, mockUpdateResult),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":           "owner",
				"repo":            "repo",
				"pullNumber":      float64(42),
				"expectedHeadSha": "abcd1234",
			},
			expectError:          false,
			expectedUpdateResult: mockUpdateResult,
		},
		{
			name: "branch update without expected SHA",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PutReposPullsUpdateBranchByOwnerByRepoByPullNumber,
					expectRequestBody(t, map[string]interface{}{}).andThen(
						mockResponse(t, http.StatusAccepted, mockUpdateResult),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
			},
			expectError:          false,
			expectedUpdateResult: mockUpdateResult,
		},
		{
			name: "branch update fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PutReposPullsUpdateBranchByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusConflict)
						_, _ = w.Write([]byte(`{"message": "Merge conflict"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
			},
			expectError:    true,
			expectedErrMsg: "failed to update pull request branch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := UpdatePullRequestBranch(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			assert.Contains(t, textContent.Text, "is in progress")
		})
	}
}

func Test_GetPullRequestComments(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := GetPullRequestComments(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_pull_request_comments", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "pullNumber")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "pullNumber"})

	// Setup mock PR comments for success case
	mockComments := []*github.PullRequestComment{
		{
			ID:      github.Ptr(int64(101)),
			Body:    github.Ptr("This looks good"),
			HTMLURL: github.Ptr("https://github.com/owner/repo/pull/42#discussion_r101"),
			User: &github.User{
				Login: github.Ptr("reviewer1"),
			},
			Path:      github.Ptr("file1.go"),
			Position:  github.Ptr(5),
			CommitID:  github.Ptr("abcdef123456"),
			CreatedAt: &github.Timestamp{Time: time.Now().Add(-24 * time.Hour)},
			UpdatedAt: &github.Timestamp{Time: time.Now().Add(-24 * time.Hour)},
		},
		{
			ID:      github.Ptr(int64(102)),
			Body:    github.Ptr("Please fix this"),
			HTMLURL: github.Ptr("https://github.com/owner/repo/pull/42#discussion_r102"),
			User: &github.User{
				Login: github.Ptr("reviewer2"),
			},
			Path:      github.Ptr("file2.go"),
			Position:  github.Ptr(10),
			CommitID:  github.Ptr("abcdef123456"),
			CreatedAt: &github.Timestamp{Time: time.Now().Add(-12 * time.Hour)},
			UpdatedAt: &github.Timestamp{Time: time.Now().Add(-12 * time.Hour)},
		},
	}

	tests := []struct {
		name             string
		mockedClient     *http.Client
		requestArgs      map[string]interface{}
		expectError      bool
		expectedComments []*github.PullRequestComment
		expectedErrMsg   string
	}{
		{
			name: "successful comments fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposPullsCommentsByOwnerByRepoByPullNumber,
					mockComments,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
			},
			expectError:      false,
			expectedComments: mockComments,
		},
		{
			name: "comments fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposPullsCommentsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(999),
			},
			expectError:    true,
			expectedErrMsg: "failed to get pull request comments",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetPullRequestComments(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedComments []*github.PullRequestComment
			err = json.Unmarshal([]byte(textContent.Text), &returnedComments)
			require.NoError(t, err)
			assert.Len(t, returnedComments, len(tc.expectedComments))
			for i, comment := range returnedComments {
				assert.Equal(t, *tc.expectedComments[i].ID, *comment.ID)
				assert.Equal(t, *tc.expectedComments[i].Body, *comment.Body)
				assert.Equal(t, *tc.expectedComments[i].User.Login, *comment.User.Login)
				assert.Equal(t, *tc.expectedComments[i].Path, *comment.Path)
				assert.Equal(t, *tc.expectedComments[i].HTMLURL, *comment.HTMLURL)
			}
		})
	}
}

func Test_GetPullRequestReviews(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := GetPullRequestReviews(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_pull_request_reviews", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "pullNumber")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "pullNumber"})

	// Setup mock PR reviews for success case
	mockReviews := []*github.PullRequestReview{
		{
			ID:      github.Ptr(int64(201)),
			State:   github.Ptr("APPROVED"),
			Body:    github.Ptr("LGTM"),
			HTMLURL: github.Ptr("https://github.com/owner/repo/pull/42#pullrequestreview-201"),
			User: &github.User{
				Login: github.Ptr("approver"),
			},
			CommitID:    github.Ptr("abcdef123456"),
			SubmittedAt: &github.Timestamp{Time: time.Now().Add(-24 * time.Hour)},
		},
		{
			ID:      github.Ptr(int64(202)),
			State:   github.Ptr("CHANGES_REQUESTED"),
			Body:    github.Ptr("Please address the following issues"),
			HTMLURL: github.Ptr("https://github.com/owner/repo/pull/42#pullrequestreview-202"),
			User: &github.User{
				Login: github.Ptr("reviewer"),
			},
			CommitID:    github.Ptr("abcdef123456"),
			SubmittedAt: &github.Timestamp{Time: time.Now().Add(-12 * time.Hour)},
		},
	}

	tests := []struct {
		name            string
		mockedClient    *http.Client
		requestArgs     map[string]interface{}
		expectError     bool
		expectedReviews []*github.PullRequestReview
		expectedErrMsg  string
	}{
		{
			name: "successful reviews fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposPullsReviewsByOwnerByRepoByPullNumber,
					mockReviews,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
			},
			expectError:     false,
			expectedReviews: mockReviews,
		},
		{
			name: "reviews fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposPullsReviewsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(999),
			},
			expectError:    true,
			expectedErrMsg: "failed to get pull request reviews",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetPullRequestReviews(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedReviews []*github.PullRequestReview
			err = json.Unmarshal([]byte(textContent.Text), &returnedReviews)
			require.NoError(t, err)
			assert.Len(t, returnedReviews, len(tc.expectedReviews))
			for i, review := range returnedReviews {
				assert.Equal(t, *tc.expectedReviews[i].ID, *review.ID)
				assert.Equal(t, *tc.expectedReviews[i].State, *review.State)
				assert.Equal(t, *tc.expectedReviews[i].Body, *review.Body)
				assert.Equal(t, *tc.expectedReviews[i].User.Login, *review.User.Login)
				assert.Equal(t, *tc.expectedReviews[i].HTMLURL, *review.HTMLURL)
			}
		})
	}
}

func Test_CreatePullRequestReview(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := CreatePullRequestReview(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "create_pull_request_review", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "pullNumber")
	assert.Contains(t, tool.InputSchema.Properties, "body")
	assert.Contains(t, tool.InputSchema.Properties, "event")
	assert.Contains(t, tool.InputSchema.Properties, "commitId")
	assert.Contains(t, tool.InputSchema.Properties, "comments")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "pullNumber", "event"})

	// Setup mock review for success case
	mockReview := &github.PullRequestReview{
		ID:      github.Ptr(int64(301)),
		State:   github.Ptr("APPROVED"),
		Body:    github.Ptr("Looks good!"),
		HTMLURL: github.Ptr("https://github.com/owner/repo/pull/42#pullrequestreview-301"),
		User: &github.User{
			Login: github.Ptr("reviewer"),
		},
		CommitID:    github.Ptr("abcdef123456"),
		SubmittedAt: &github.Timestamp{Time: time.Now()},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedReview *github.PullRequestReview
		expectedErrMsg string
	}{
		{
			name: "successful review creation with body only",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsReviewsByOwnerByRepoByPullNumber,
					expectRequestBody(t, map[string]interface{}{
						"body":  "Looks good!",
						"event": "APPROVE",
					}).andThen(
						mockResponse(t, http.StatusOK, mockReview),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"body":       "Looks good!",
				"event":      "APPROVE",
			},
			expectError:    false,
			expectedReview: mockReview,
		},
		{
			name: "successful review creation with commitId",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsReviewsByOwnerByRepoByPullNumber,
					expectRequestBody(t, map[string]interface{}{
						"body":      "Looks good!",
						"event":     "APPROVE",
						"commit_id": "abcdef123456",
					}).andThen(
						mockResponse(t, http.StatusOK, mockReview),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"body":       "Looks good!",
				"event":      "APPROVE",
				"commitId":   "abcdef123456",
			},
			expectError:    false,
			expectedReview: mockReview,
		},
		{
			name: "successful review creation with comments",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsReviewsByOwnerByRepoByPullNumber,
					expectRequestBody(t, map[string]interface{}{
						"body":  "Some issues to fix",
						"event": "REQUEST_CHANGES",
						"comments": []interface{}{
							map[string]interface{}{
								"path":     "file1.go",
								"position": float64(10),
								"body":     "This needs to be fixed",
							},
							map[string]interface{}{
								"path":     "file2.go",
								"position": float64(20),
								"body":     "Consider a different approach here",
							},
						},
					}).andThen(
						mockResponse(t, http.StatusOK, mockReview),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"body":       "Some issues to fix",
				"event":      "REQUEST_CHANGES",
				"comments": []interface{}{
					map[string]interface{}{
						"path":     "file1.go",
						"position": float64(10),
						"body":     "This needs to be fixed",
					},
					map[string]interface{}{
						"path":     "file2.go",
						"position": float64(20),
						"body":     "Consider a different approach here",
					},
				},
			},
			expectError:    false,
			expectedReview: mockReview,
		},
		{
			name: "invalid comment format",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsReviewsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message": "Invalid comment format"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"event":      "REQUEST_CHANGES",
				"comments": []interface{}{
					map[string]interface{}{
						"path": "file1.go",
						// missing position
						"body": "This needs to be fixed",
					},
				},
			},
			expectError:    false,
			expectedErrMsg: "each comment must have either position or line",
		},
		{
			name: "successful review creation with line parameter",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsReviewsByOwnerByRepoByPullNumber,
					expectRequestBody(t, map[string]interface{}{
						"body":  "Code review comments",
						"event": "COMMENT",
						"comments": []interface{}{
							map[string]interface{}{
								"path": "main.go",
								"line": float64(42),
								"body": "Consider adding a comment here",
							},
						},
					}).andThen(
						mockResponse(t, http.StatusOK, mockReview),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"body":       "Code review comments",
				"event":      "COMMENT",
				"comments": []interface{}{
					map[string]interface{}{
						"path": "main.go",
						"line": float64(42),
						"body": "Consider adding a comment here",
					},
				},
			},
			expectError:    false,
			expectedReview: mockReview,
		},
		{
			name: "successful review creation with multi-line comment",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsReviewsByOwnerByRepoByPullNumber,
					expectRequestBody(t, map[string]interface{}{
						"body":  "Multi-line comment review",
						"event": "COMMENT",
						"comments": []interface{}{
							map[string]interface{}{
								"path":       "main.go",
								"start_line": float64(10),
								"line":       float64(15),
								"side":       "RIGHT",
								"body":       "This entire block needs refactoring",
							},
						},
					}).andThen(
						mockResponse(t, http.StatusOK, mockReview),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"body":       "Multi-line comment review",
				"event":      "COMMENT",
				"comments": []interface{}{
					map[string]interface{}{
						"path":       "main.go",
						"start_line": float64(10),
						"line":       float64(15),
						"side":       "RIGHT",
						"body":       "This entire block needs refactoring",
					},
				},
			},
			expectError:    false,
			expectedReview: mockReview,
		},
		{
			name:         "invalid multi-line comment - missing line parameter",
			mockedClient: mock.NewMockedHTTPClient(),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"event":      "COMMENT",
				"comments": []interface{}{
					map[string]interface{}{
						"path":       "main.go",
						"start_line": float64(10),
						// missing line parameter
						"body": "Invalid multi-line comment",
					},
				},
			},
			expectError:    false,
			expectedErrMsg: "each comment must have either position or line", // Updated error message
		},
		{
			name: "invalid comment - mixing position with line parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.PostReposPullsReviewsByOwnerByRepoByPullNumber,
					mockReview,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"event":      "COMMENT",
				"comments": []interface{}{
					map[string]interface{}{
						"path":     "main.go",
						"position": float64(5),
						"line":     float64(42),
						"body":     "Invalid parameter combination",
					},
				},
			},
			expectError:    false,
			expectedErrMsg: "position cannot be combined with line, side, start_line, or start_side",
		},
		{
			name:         "invalid multi-line comment - missing side parameter",
			mockedClient: mock.NewMockedHTTPClient(),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"event":      "COMMENT",
				"comments": []interface{}{
					map[string]interface{}{
						"path":       "main.go",
						"start_line": float64(10),
						"line":       float64(15),
						"start_side": "LEFT",
						// missing side parameter
						"body": "Invalid multi-line comment",
					},
				},
			},
			expectError:    false,
			expectedErrMsg: "if start_side is provided, side must also be provided",
		},
		{
			name: "review creation fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsReviewsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message": "Invalid comment format"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":      "owner",
				"repo":       "repo",
				"pullNumber": float64(42),
				"body":       "Looks good!",
				"event":      "APPROVE",
			},
			expectError:    true,
			expectedErrMsg: "failed to create pull request review",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := CreatePullRequestReview(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// For error messages in the result
			if tc.expectedErrMsg != "" {
				textContent := getTextResult(t, result)
				assert.Contains(t, textContent.Text, tc.expectedErrMsg)
				return
			}

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedReview github.PullRequestReview
			err = json.Unmarshal([]byte(textContent.Text), &returnedReview)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedReview.ID, *returnedReview.ID)
			assert.Equal(t, *tc.expectedReview.State, *returnedReview.State)
			assert.Equal(t, *tc.expectedReview.Body, *returnedReview.Body)
			assert.Equal(t, *tc.expectedReview.User.Login, *returnedReview.User.Login)
			assert.Equal(t, *tc.expectedReview.HTMLURL, *returnedReview.HTMLURL)
		})
	}
}

func Test_CreatePullRequest(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := CreatePullRequest(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "create_pull_request", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "title")
	assert.Contains(t, tool.InputSchema.Properties, "body")
	assert.Contains(t, tool.InputSchema.Properties, "head")
	assert.Contains(t, tool.InputSchema.Properties, "base")
	assert.Contains(t, tool.InputSchema.Properties, "draft")
	assert.Contains(t, tool.InputSchema.Properties, "maintainer_can_modify")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "title", "head", "base"})

	// Setup mock PR for success case
	mockPR := &github.PullRequest{
		Number:  github.Ptr(42),
		Title:   github.Ptr("Test PR"),
		State:   github.Ptr("open"),
		HTMLURL: github.Ptr("https://github.com/owner/repo/pull/42"),
		Head: &github.PullRequestBranch{
			SHA: github.Ptr("abcd1234"),
			Ref: github.Ptr("feature-branch"),
		},
		Base: &github.PullRequestBranch{
			SHA: github.Ptr("efgh5678"),
			Ref: github.Ptr("main"),
		},
		Body:                github.Ptr("This is a test PR"),
		Draft:               github.Ptr(false),
		MaintainerCanModify: github.Ptr(true),
		User: &github.User{
			Login: github.Ptr("testuser"),
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedPR     *github.PullRequest
		expectedErrMsg string
	}{
		{
			name: "successful PR creation",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsByOwnerByRepo,
					expectRequestBody(t, map[string]interface{}{
						"title":                 "Test PR",
						"body":                  "This is a test PR",
						"head":                  "feature-branch",
						"base":                  "main",
						"draft":                 false,
						"maintainer_can_modify": true,
					}).andThen(
						mockResponse(t, http.StatusCreated, mockPR),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":                 "owner",
				"repo":                  "repo",
				"title":                 "Test PR",
				"body":                  "This is a test PR",
				"head":                  "feature-branch",
				"base":                  "main",
				"draft":                 false,
				"maintainer_can_modify": true,
			},
			expectError: false,
			expectedPR:  mockPR,
		},
		{
			name:         "missing required parameter",
			mockedClient: mock.NewMockedHTTPClient(),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
				// missing title, head, base
			},
			expectError:    true,
			expectedErrMsg: "missing required parameter: title",
		},
		{
			name: "PR creation fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsByOwnerByRepo,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message":"Validation failed","errors":[{"resource":"PullRequest","code":"invalid"}]}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
				"title": "Test PR",
				"head":  "feature-branch",
				"base":  "main",
			},
			expectError:    true,
			expectedErrMsg: "failed to create pull request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := CreatePullRequest(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				if err != nil {
					assert.Contains(t, err.Error(), tc.expectedErrMsg)
					return
				}

				// If no error returned but in the result
				textContent := getTextResult(t, result)
				assert.Contains(t, textContent.Text, tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedPR github.PullRequest
			err = json.Unmarshal([]byte(textContent.Text), &returnedPR)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedPR.Number, *returnedPR.Number)
			assert.Equal(t, *tc.expectedPR.Title, *returnedPR.Title)
			assert.Equal(t, *tc.expectedPR.State, *returnedPR.State)
			assert.Equal(t, *tc.expectedPR.HTMLURL, *returnedPR.HTMLURL)
			assert.Equal(t, *tc.expectedPR.Head.SHA, *returnedPR.Head.SHA)
			assert.Equal(t, *tc.expectedPR.Base.Ref, *returnedPR.Base.Ref)
			assert.Equal(t, *tc.expectedPR.Body, *returnedPR.Body)
			assert.Equal(t, *tc.expectedPR.User.Login, *returnedPR.User.Login)
		})
	}
}

func Test_AddPullRequestReviewComment(t *testing.T) {
	mockClient := github.NewClient(nil)
	tool, _ := AddPullRequestReviewComment(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "add_pull_request_review_comment", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "pull_number")
	assert.Contains(t, tool.InputSchema.Properties, "body")
	assert.Contains(t, tool.InputSchema.Properties, "commit_id")
	assert.Contains(t, tool.InputSchema.Properties, "path")
	// Since we've updated commit_id and path to be optional when using in_reply_to
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "pull_number", "body"})

	mockComment := &github.PullRequestComment{
		ID:   github.Ptr(int64(123)),
		Body: github.Ptr("Great stuff!"),
		Path: github.Ptr("file1.txt"),
		Line: github.Ptr(2),
		Side: github.Ptr("RIGHT"),
	}

	mockReply := &github.PullRequestComment{
		ID:   github.Ptr(int64(456)),
		Body: github.Ptr("Good point, will fix!"),
	}

	tests := []struct {
		name            string
		mockedClient    *http.Client
		requestArgs     map[string]interface{}
		expectError     bool
		expectedComment *github.PullRequestComment
		expectedErrMsg  string
	}{
		{
			name: "successful line comment creation",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsCommentsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusCreated)
						err := json.NewEncoder(w).Encode(mockComment)
						if err != nil {
							http.Error(w, err.Error(), http.StatusInternalServerError)
							return
						}
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"pull_number": float64(1),
				"body":        "Great stuff!",
				"commit_id":   "6dcb09b5b57875f334f61aebed695e2e4193db5e",
				"path":        "file1.txt",
				"line":        float64(2),
				"side":        "RIGHT",
			},
			expectError:     false,
			expectedComment: mockComment,
		},
		{
			name: "successful reply using in_reply_to",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsCommentsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusCreated)
						err := json.NewEncoder(w).Encode(mockReply)
						if err != nil {
							http.Error(w, err.Error(), http.StatusInternalServerError)
							return
						}
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"pull_number": float64(1),
				"body":        "Good point, will fix!",
				"in_reply_to": float64(123),
			},
			expectError:     false,
			expectedComment: mockReply,
		},
		{
			name: "comment creation fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsCommentsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"message": "Validation Failed"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"pull_number": float64(1),
				"body":        "Great stuff!",
				"commit_id":   "6dcb09b5b57875f334f61aebed695e2e4193db5e",
				"path":        "file1.txt",
				"line":        float64(2),
			},
			expectError:    true,
			expectedErrMsg: "failed to create pull request comment",
		},
		{
			name: "reply creation fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposPullsCommentsByOwnerByRepoByPullNumber,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"message": "Comment not found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"pull_number": float64(1),
				"body":        "Good point, will fix!",
				"in_reply_to": float64(999),
			},
			expectError:    true,
			expectedErrMsg: "failed to reply to pull request comment",
		},
		{
			name:         "missing required parameters for comment",
			mockedClient: mock.NewMockedHTTPClient(),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"pull_number": float64(1),
				"body":        "Great stuff!",
				// missing commit_id and path
			},
			expectError:    false,
			expectedErrMsg: "missing required parameter: commit_id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := github.NewClient(tc.mockedClient)

			_, handler := AddPullRequestReviewComment(stubGetClientFn(mockClient), translations.NullTranslationHelper)

			request := createMCPRequest(tc.requestArgs)

			result, err := handler(context.Background(), request)

			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)
			require.Len(t, result.Content, 1)

			textContent := getTextResult(t, result)
			if tc.expectedErrMsg != "" {
				assert.Contains(t, textContent.Text, tc.expectedErrMsg)
				return
			}

			var returnedComment github.PullRequestComment
			err = json.Unmarshal([]byte(getTextResult(t, result).Text), &returnedComment)
			require.NoError(t, err)

			assert.Equal(t, *tc.expectedComment.ID, *returnedComment.ID)
			assert.Equal(t, *tc.expectedComment.Body, *returnedComment.Body)

			// Only check Path, Line, and Side if they exist in the expected comment
			if tc.expectedComment.Path != nil {
				assert.Equal(t, *tc.expectedComment.Path, *returnedComment.Path)
			}
			if tc.expectedComment.Line != nil {
				assert.Equal(t, *tc.expectedComment.Line, *returnedComment.Line)
			}
			if tc.expectedComment.Side != nil {
				assert.Equal(t, *tc.expectedComment.Side, *returnedComment.Side)
			}
		})
	}
}
```

---

## `pkg/github/repositories.go`

```go
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func GetCommit(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_commit",
			mcp.WithDescription(t("TOOL_GET_COMMITS_DESCRIPTION", "Get details for a commit from a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("sha",
				mcp.Required(),
				mcp.Description("Commit SHA, branch name, or tag name"),
			),
			WithPagination(),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			sha, err := requiredParam[string](request, "sha")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pagination, err := OptionalPaginationParams(request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.ListOptions{
				Page:    pagination.page,
				PerPage: pagination.perPage,
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			commit, resp, err := client.Repositories.GetCommit(ctx, owner, repo, sha, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to get commit: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != 200 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get commit: %s", string(body))), nil
			}

			r, err := json.Marshal(commit)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// ListCommits creates a tool to get commits of a branch in a repository.
func ListCommits(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("list_commits",
			mcp.WithDescription(t("TOOL_LIST_COMMITS_DESCRIPTION", "Get list of commits of a branch in a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("sha",
				mcp.Description("Branch name"),
			),
			WithPagination(),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			sha, err := OptionalParam[string](request, "sha")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pagination, err := OptionalPaginationParams(request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.CommitsListOptions{
				SHA: sha,
				ListOptions: github.ListOptions{
					Page:    pagination.page,
					PerPage: pagination.perPage,
				},
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			commits, resp, err := client.Repositories.ListCommits(ctx, owner, repo, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to list commits: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != 200 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to list commits: %s", string(body))), nil
			}

			r, err := json.Marshal(commits)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// ListBranches creates a tool to list branches in a GitHub repository.
func ListBranches(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("list_branches",
			mcp.WithDescription(t("TOOL_LIST_BRANCHES_DESCRIPTION", "List branches in a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			WithPagination(),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pagination, err := OptionalPaginationParams(request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.BranchListOptions{
				ListOptions: github.ListOptions{
					Page:    pagination.page,
					PerPage: pagination.perPage,
				},
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}

			branches, resp, err := client.Repositories.ListBranches(ctx, owner, repo, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to list branches: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to list branches: %s", string(body))), nil
			}

			r, err := json.Marshal(branches)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// CreateOrUpdateFile creates a tool to create or update a file in a GitHub repository.
func CreateOrUpdateFile(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("create_or_update_file",
			mcp.WithDescription(t("TOOL_CREATE_OR_UPDATE_FILE_DESCRIPTION", "Create or update a single file in a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner (username or organization)"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("Path where to create/update the file"),
			),
			mcp.WithString("content",
				mcp.Required(),
				mcp.Description("Content of the file"),
			),
			mcp.WithString("message",
				mcp.Required(),
				mcp.Description("Commit message"),
			),
			mcp.WithString("branch",
				mcp.Required(),
				mcp.Description("Branch to create/update the file in"),
			),
			mcp.WithString("sha",
				mcp.Description("SHA of file being replaced (for updates)"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			path, err := requiredParam[string](request, "path")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			content, err := requiredParam[string](request, "content")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			message, err := requiredParam[string](request, "message")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			branch, err := requiredParam[string](request, "branch")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Convert content to base64
			contentBytes := []byte(content)

			// Create the file options
			opts := &github.RepositoryContentFileOptions{
				Message: github.Ptr(message),
				Content: contentBytes,
				Branch:  github.Ptr(branch),
			}

			// If SHA is provided, set it (for updates)
			sha, err := OptionalParam[string](request, "sha")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if sha != "" {
				opts.SHA = github.Ptr(sha)
			}

			// Create or update the file
			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			fileContent, resp, err := client.Repositories.CreateFile(ctx, owner, repo, path, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to create/update file: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != 200 && resp.StatusCode != 201 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to create/update file: %s", string(body))), nil
			}

			r, err := json.Marshal(fileContent)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// CreateRepository creates a tool to create a new GitHub repository.
func CreateRepository(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("create_repository",
			mcp.WithDescription(t("TOOL_CREATE_REPOSITORY_DESCRIPTION", "Create a new GitHub repository in your account")),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("description",
				mcp.Description("Repository description"),
			),
			mcp.WithBoolean("private",
				mcp.Description("Whether repo should be private"),
			),
			mcp.WithBoolean("autoInit",
				mcp.Description("Initialize with README"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name, err := requiredParam[string](request, "name")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			description, err := OptionalParam[string](request, "description")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			private, err := OptionalParam[bool](request, "private")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			autoInit, err := OptionalParam[bool](request, "autoInit")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			repo := &github.Repository{
				Name:        github.Ptr(name),
				Description: github.Ptr(description),
				Private:     github.Ptr(private),
				AutoInit:    github.Ptr(autoInit),
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			createdRepo, resp, err := client.Repositories.Create(ctx, "", repo)
			if err != nil {
				return nil, fmt.Errorf("failed to create repository: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusCreated {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to create repository: %s", string(body))), nil
			}

			r, err := json.Marshal(createdRepo)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// GetFileContents creates a tool to get the contents of a file or directory from a GitHub repository.
func GetFileContents(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("get_file_contents",
			mcp.WithDescription(t("TOOL_GET_FILE_CONTENTS_DESCRIPTION", "Get the contents of a file or directory from a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner (username or organization)"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("Path to file/directory"),
			),
			mcp.WithString("branch",
				mcp.Description("Branch to get contents from"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			path, err := requiredParam[string](request, "path")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			branch, err := OptionalParam[string](request, "branch")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			opts := &github.RepositoryContentGetOptions{Ref: branch}
			fileContent, dirContent, resp, err := client.Repositories.GetContents(ctx, owner, repo, path, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to get file contents: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != 200 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to get file contents: %s", string(body))), nil
			}

			var result interface{}
			if fileContent != nil {
				result = fileContent
			} else {
				result = dirContent
			}

			r, err := json.Marshal(result)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// ForkRepository creates a tool to fork a repository.
func ForkRepository(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("fork_repository",
			mcp.WithDescription(t("TOOL_FORK_REPOSITORY_DESCRIPTION", "Fork a GitHub repository to your account or specified organization")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("organization",
				mcp.Description("Organization to fork to"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			org, err := OptionalParam[string](request, "organization")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.RepositoryCreateForkOptions{}
			if org != "" {
				opts.Organization = org
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			forkedRepo, resp, err := client.Repositories.CreateFork(ctx, owner, repo, opts)
			if err != nil {
				// Check if it's an acceptedError. An acceptedError indicates that the update is in progress,
				// and it's not a real error.
				if resp != nil && resp.StatusCode == http.StatusAccepted && isAcceptedError(err) {
					return mcp.NewToolResultText("Fork is in progress"), nil
				}
				return nil, fmt.Errorf("failed to fork repository: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusAccepted {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to fork repository: %s", string(body))), nil
			}

			r, err := json.Marshal(forkedRepo)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// CreateBranch creates a tool to create a new branch.
func CreateBranch(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("create_branch",
			mcp.WithDescription(t("TOOL_CREATE_BRANCH_DESCRIPTION", "Create a new branch in a GitHub repository")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("branch",
				mcp.Required(),
				mcp.Description("Name for new branch"),
			),
			mcp.WithString("from_branch",
				mcp.Description("Source branch (defaults to repo default)"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			branch, err := requiredParam[string](request, "branch")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			fromBranch, err := OptionalParam[string](request, "from_branch")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}

			// Get the source branch SHA
			var ref *github.Reference

			if fromBranch == "" {
				// Get default branch if from_branch not specified
				repository, resp, err := client.Repositories.Get(ctx, owner, repo)
				if err != nil {
					return nil, fmt.Errorf("failed to get repository: %w", err)
				}
				defer func() { _ = resp.Body.Close() }()

				fromBranch = *repository.DefaultBranch
			}

			// Get SHA of source branch
			ref, resp, err := client.Git.GetRef(ctx, owner, repo, "refs/heads/"+fromBranch)
			if err != nil {
				return nil, fmt.Errorf("failed to get reference: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			// Create new branch
			newRef := &github.Reference{
				Ref:    github.Ptr("refs/heads/" + branch),
				Object: &github.GitObject{SHA: ref.Object.SHA},
			}

			createdRef, resp, err := client.Git.CreateRef(ctx, owner, repo, newRef)
			if err != nil {
				return nil, fmt.Errorf("failed to create branch: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			r, err := json.Marshal(createdRef)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// PushFiles creates a tool to push multiple files in a single commit to a GitHub repository.
func PushFiles(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("push_files",
			mcp.WithDescription(t("TOOL_PUSH_FILES_DESCRIPTION", "Push multiple files to a GitHub repository in a single commit")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("Repository owner"),
			),
			mcp.WithString("repo",
				mcp.Required(),
				mcp.Description("Repository name"),
			),
			mcp.WithString("branch",
				mcp.Required(),
				mcp.Description("Branch to push to"),
			),
			mcp.WithArray("files",
				mcp.Required(),
				mcp.Items(
					map[string]interface{}{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"path", "content"},
						"properties": map[string]interface{}{
							"path": map[string]interface{}{
								"type":        "string",
								"description": "path to the file",
							},
							"content": map[string]interface{}{
								"type":        "string",
								"description": "file content",
							},
						},
					}),
				mcp.Description("Array of file objects to push, each object with path (string) and content (string)"),
			),
			mcp.WithString("message",
				mcp.Required(),
				mcp.Description("Commit message"),
			),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner, err := requiredParam[string](request, "owner")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			repo, err := requiredParam[string](request, "repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			branch, err := requiredParam[string](request, "branch")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			message, err := requiredParam[string](request, "message")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Parse files parameter - this should be an array of objects with path and content
			filesObj, ok := request.Params.Arguments["files"].([]interface{})
			if !ok {
				return mcp.NewToolResultError("files parameter must be an array of objects with path and content"), nil
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}

			// Get the reference for the branch
			ref, resp, err := client.Git.GetRef(ctx, owner, repo, "refs/heads/"+branch)
			if err != nil {
				return nil, fmt.Errorf("failed to get branch reference: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			// Get the commit object that the branch points to
			baseCommit, resp, err := client.Git.GetCommit(ctx, owner, repo, *ref.Object.SHA)
			if err != nil {
				return nil, fmt.Errorf("failed to get base commit: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			// Create tree entries for all files
			var entries []*github.TreeEntry

			for _, file := range filesObj {
				fileMap, ok := file.(map[string]interface{})
				if !ok {
					return mcp.NewToolResultError("each file must be an object with path and content"), nil
				}

				path, ok := fileMap["path"].(string)
				if !ok || path == "" {
					return mcp.NewToolResultError("each file must have a path"), nil
				}

				content, ok := fileMap["content"].(string)
				if !ok {
					return mcp.NewToolResultError("each file must have content"), nil
				}

				// Create a tree entry for the file
				entries = append(entries, &github.TreeEntry{
					Path:    github.Ptr(path),
					Mode:    github.Ptr("100644"), // Regular file mode
					Type:    github.Ptr("blob"),
					Content: github.Ptr(content),
				})
			}

			// Create a new tree with the file entries
			newTree, resp, err := client.Git.CreateTree(ctx, owner, repo, *baseCommit.Tree.SHA, entries)
			if err != nil {
				return nil, fmt.Errorf("failed to create tree: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			// Create a new commit
			commit := &github.Commit{
				Message: github.Ptr(message),
				Tree:    newTree,
				Parents: []*github.Commit{{SHA: baseCommit.SHA}},
			}
			newCommit, resp, err := client.Git.CreateCommit(ctx, owner, repo, commit, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create commit: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			// Update the reference to point to the new commit
			ref.Object.SHA = newCommit.SHA
			updatedRef, resp, err := client.Git.UpdateRef(ctx, owner, repo, ref, false)
			if err != nil {
				return nil, fmt.Errorf("failed to update reference: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			r, err := json.Marshal(updatedRef)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}
```

---

## `pkg/github/repositories_test.go`

```go
package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetFileContents(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := GetFileContents(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_file_contents", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "path")
	assert.Contains(t, tool.InputSchema.Properties, "branch")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "path"})

	// Setup mock file content for success case
	mockFileContent := &github.RepositoryContent{
		Type:        github.Ptr("file"),
		Name:        github.Ptr("README.md"),
		Path:        github.Ptr("README.md"),
		Content:     github.Ptr("IyBUZXN0IFJlcG9zaXRvcnkKClRoaXMgaXMgYSB0ZXN0IHJlcG9zaXRvcnku"), // Base64 encoded "# Test Repository\n\nThis is a test repository."
		SHA:         github.Ptr("abc123"),
		Size:        github.Ptr(42),
		HTMLURL:     github.Ptr("https://github.com/owner/repo/blob/main/README.md"),
		DownloadURL: github.Ptr("https://raw.githubusercontent.com/owner/repo/main/README.md"),
	}

	// Setup mock directory content for success case
	mockDirContent := []*github.RepositoryContent{
		{
			Type:    github.Ptr("file"),
			Name:    github.Ptr("README.md"),
			Path:    github.Ptr("README.md"),
			SHA:     github.Ptr("abc123"),
			Size:    github.Ptr(42),
			HTMLURL: github.Ptr("https://github.com/owner/repo/blob/main/README.md"),
		},
		{
			Type:    github.Ptr("dir"),
			Name:    github.Ptr("src"),
			Path:    github.Ptr("src"),
			SHA:     github.Ptr("def456"),
			HTMLURL: github.Ptr("https://github.com/owner/repo/tree/main/src"),
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedResult interface{}
		expectedErrMsg string
	}{
		{
			name: "successful file content fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposContentsByOwnerByRepoByPath,
					expectQueryParams(t, map[string]string{
						"ref": "main",
					}).andThen(
						mockResponse(t, http.StatusOK, mockFileContent),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":  "owner",
				"repo":   "repo",
				"path":   "README.md",
				"branch": "main",
			},
			expectError:    false,
			expectedResult: mockFileContent,
		},
		{
			name: "successful directory content fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposContentsByOwnerByRepoByPath,
					expectQueryParams(t, map[string]string{}).andThen(
						mockResponse(t, http.StatusOK, mockDirContent),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
				"path":  "src",
			},
			expectError:    false,
			expectedResult: mockDirContent,
		},
		{
			name: "content fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposContentsByOwnerByRepoByPath,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":  "owner",
				"repo":   "repo",
				"path":   "nonexistent.md",
				"branch": "main",
			},
			expectError:    true,
			expectedErrMsg: "failed to get file contents",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetFileContents(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := mcp.CallToolRequest{
				Params: struct {
					Name      string                 `json:"name"`
					Arguments map[string]interface{} `json:"arguments,omitempty"`
					Meta      *struct {
						ProgressToken mcp.ProgressToken `json:"progressToken,omitempty"`
					} `json:"_meta,omitempty"`
				}{
					Arguments: tc.requestArgs,
				},
			}

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Verify based on expected type
			switch expected := tc.expectedResult.(type) {
			case *github.RepositoryContent:
				var returnedContent github.RepositoryContent
				err = json.Unmarshal([]byte(textContent.Text), &returnedContent)
				require.NoError(t, err)
				assert.Equal(t, *expected.Name, *returnedContent.Name)
				assert.Equal(t, *expected.Path, *returnedContent.Path)
				assert.Equal(t, *expected.Type, *returnedContent.Type)
			case []*github.RepositoryContent:
				var returnedContents []*github.RepositoryContent
				err = json.Unmarshal([]byte(textContent.Text), &returnedContents)
				require.NoError(t, err)
				assert.Len(t, returnedContents, len(expected))
				for i, content := range returnedContents {
					assert.Equal(t, *expected[i].Name, *content.Name)
					assert.Equal(t, *expected[i].Path, *content.Path)
					assert.Equal(t, *expected[i].Type, *content.Type)
				}
			}
		})
	}
}

func Test_ForkRepository(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := ForkRepository(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "fork_repository", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "organization")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo"})

	// Setup mock forked repo for success case
	mockForkedRepo := &github.Repository{
		ID:       github.Ptr(int64(123456)),
		Name:     github.Ptr("repo"),
		FullName: github.Ptr("new-owner/repo"),
		Owner: &github.User{
			Login: github.Ptr("new-owner"),
		},
		HTMLURL:       github.Ptr("https://github.com/new-owner/repo"),
		DefaultBranch: github.Ptr("main"),
		Fork:          github.Ptr(true),
		ForksCount:    github.Ptr(0),
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedRepo   *github.Repository
		expectedErrMsg string
	}{
		{
			name: "successful repository fork",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposForksByOwnerByRepo,
					mockResponse(t, http.StatusAccepted, mockForkedRepo),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
			},
			expectError:  false,
			expectedRepo: mockForkedRepo,
		},
		{
			name: "repository fork fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PostReposForksByOwnerByRepo,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte(`{"message": "Forbidden"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
			},
			expectError:    true,
			expectedErrMsg: "failed to fork repository",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := ForkRepository(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			assert.Contains(t, textContent.Text, "Fork is in progress")
		})
	}
}

func Test_CreateBranch(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := CreateBranch(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "create_branch", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "branch")
	assert.Contains(t, tool.InputSchema.Properties, "from_branch")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "branch"})

	// Setup mock repository for default branch test
	mockRepo := &github.Repository{
		DefaultBranch: github.Ptr("main"),
	}

	// Setup mock reference for from_branch tests
	mockSourceRef := &github.Reference{
		Ref: github.Ptr("refs/heads/main"),
		Object: &github.GitObject{
			SHA: github.Ptr("abc123def456"),
		},
	}

	// Setup mock created reference
	mockCreatedRef := &github.Reference{
		Ref: github.Ptr("refs/heads/new-feature"),
		Object: &github.GitObject{
			SHA: github.Ptr("abc123def456"),
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedRef    *github.Reference
		expectedErrMsg string
	}{
		{
			name: "successful branch creation with from_branch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposGitRefByOwnerByRepoByRef,
					mockSourceRef,
				),
				mock.WithRequestMatch(
					mock.PostReposGitRefsByOwnerByRepo,
					mockCreatedRef,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"branch":      "new-feature",
				"from_branch": "main",
			},
			expectError: false,
			expectedRef: mockCreatedRef,
		},
		{
			name: "successful branch creation with default branch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposByOwnerByRepo,
					mockRepo,
				),
				mock.WithRequestMatch(
					mock.GetReposGitRefByOwnerByRepoByRef,
					mockSourceRef,
				),
				mock.WithRequestMatchHandler(
					mock.PostReposGitRefsByOwnerByRepo,
					expectRequestBody(t, map[string]interface{}{
						"ref": "refs/heads/new-feature",
						"sha": "abc123def456",
					}).andThen(
						mockResponse(t, http.StatusCreated, mockCreatedRef),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":  "owner",
				"repo":   "repo",
				"branch": "new-feature",
			},
			expectError: false,
			expectedRef: mockCreatedRef,
		},
		{
			name: "fail to get repository",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposByOwnerByRepo,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Repository not found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":  "owner",
				"repo":   "nonexistent-repo",
				"branch": "new-feature",
			},
			expectError:    true,
			expectedErrMsg: "failed to get repository",
		},
		{
			name: "fail to get reference",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposGitRefByOwnerByRepoByRef,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Reference not found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"branch":      "new-feature",
				"from_branch": "nonexistent-branch",
			},
			expectError:    true,
			expectedErrMsg: "failed to get reference",
		},
		{
			name: "fail to create branch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposGitRefByOwnerByRepoByRef,
					mockSourceRef,
				),
				mock.WithRequestMatchHandler(
					mock.PostReposGitRefsByOwnerByRepo,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message": "Reference already exists"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"branch":      "existing-branch",
				"from_branch": "main",
			},
			expectError:    true,
			expectedErrMsg: "failed to create branch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := CreateBranch(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedRef github.Reference
			err = json.Unmarshal([]byte(textContent.Text), &returnedRef)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedRef.Ref, *returnedRef.Ref)
			assert.Equal(t, *tc.expectedRef.Object.SHA, *returnedRef.Object.SHA)
		})
	}
}

func Test_GetCommit(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := GetCommit(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "get_commit", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "sha")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "sha"})

	mockCommit := &github.RepositoryCommit{
		SHA: github.Ptr("abc123def456"),
		Commit: &github.Commit{
			Message: github.Ptr("First commit"),
			Author: &github.CommitAuthor{
				Name:  github.Ptr("Test User"),
				Email: github.Ptr("test@example.com"),
				Date:  &github.Timestamp{Time: time.Now().Add(-48 * time.Hour)},
			},
		},
		Author: &github.User{
			Login: github.Ptr("testuser"),
		},
		HTMLURL: github.Ptr("https://github.com/owner/repo/commit/abc123def456"),
		Stats: &github.CommitStats{
			Additions: github.Ptr(10),
			Deletions: github.Ptr(2),
			Total:     github.Ptr(12),
		},
		Files: []*github.CommitFile{
			{
				Filename:  github.Ptr("file1.go"),
				Status:    github.Ptr("modified"),
				Additions: github.Ptr(10),
				Deletions: github.Ptr(2),
				Changes:   github.Ptr(12),
				Patch:     github.Ptr("@@ -1,2 +1,10 @@"),
			},
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedCommit *github.RepositoryCommit
		expectedErrMsg string
	}{
		{
			name: "successful commit fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposCommitsByOwnerByRepoByRef,
					mockResponse(t, http.StatusOK, mockCommit),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
				"sha":   "abc123def456",
			},
			expectError:    false,
			expectedCommit: mockCommit,
		},
		{
			name: "commit fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposCommitsByOwnerByRepoByRef,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
				"sha":   "nonexistent-sha",
			},
			expectError:    true,
			expectedErrMsg: "failed to get commit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := GetCommit(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedCommit github.RepositoryCommit
			err = json.Unmarshal([]byte(textContent.Text), &returnedCommit)
			require.NoError(t, err)

			assert.Equal(t, *tc.expectedCommit.SHA, *returnedCommit.SHA)
			assert.Equal(t, *tc.expectedCommit.Commit.Message, *returnedCommit.Commit.Message)
			assert.Equal(t, *tc.expectedCommit.Author.Login, *returnedCommit.Author.Login)
			assert.Equal(t, *tc.expectedCommit.HTMLURL, *returnedCommit.HTMLURL)
		})
	}
}

func Test_ListCommits(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := ListCommits(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "list_commits", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "sha")
	assert.Contains(t, tool.InputSchema.Properties, "page")
	assert.Contains(t, tool.InputSchema.Properties, "perPage")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo"})

	// Setup mock commits for success case
	mockCommits := []*github.RepositoryCommit{
		{
			SHA: github.Ptr("abc123def456"),
			Commit: &github.Commit{
				Message: github.Ptr("First commit"),
				Author: &github.CommitAuthor{
					Name:  github.Ptr("Test User"),
					Email: github.Ptr("test@example.com"),
					Date:  &github.Timestamp{Time: time.Now().Add(-48 * time.Hour)},
				},
			},
			Author: &github.User{
				Login: github.Ptr("testuser"),
			},
			HTMLURL: github.Ptr("https://github.com/owner/repo/commit/abc123def456"),
		},
		{
			SHA: github.Ptr("def456abc789"),
			Commit: &github.Commit{
				Message: github.Ptr("Second commit"),
				Author: &github.CommitAuthor{
					Name:  github.Ptr("Another User"),
					Email: github.Ptr("another@example.com"),
					Date:  &github.Timestamp{Time: time.Now().Add(-24 * time.Hour)},
				},
			},
			Author: &github.User{
				Login: github.Ptr("anotheruser"),
			},
			HTMLURL: github.Ptr("https://github.com/owner/repo/commit/def456abc789"),
		},
	}

	tests := []struct {
		name            string
		mockedClient    *http.Client
		requestArgs     map[string]interface{}
		expectError     bool
		expectedCommits []*github.RepositoryCommit
		expectedErrMsg  string
	}{
		{
			name: "successful commits fetch with default params",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposCommitsByOwnerByRepo,
					mockCommits,
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
			},
			expectError:     false,
			expectedCommits: mockCommits,
		},
		{
			name: "successful commits fetch with branch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposCommitsByOwnerByRepo,
					expectQueryParams(t, map[string]string{
						"sha":      "main",
						"page":     "1",
						"per_page": "30",
					}).andThen(
						mockResponse(t, http.StatusOK, mockCommits),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
				"sha":   "main",
			},
			expectError:     false,
			expectedCommits: mockCommits,
		},
		{
			name: "successful commits fetch with pagination",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposCommitsByOwnerByRepo,
					expectQueryParams(t, map[string]string{
						"page":     "2",
						"per_page": "10",
					}).andThen(
						mockResponse(t, http.StatusOK, mockCommits),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":   "owner",
				"repo":    "repo",
				"page":    float64(2),
				"perPage": float64(10),
			},
			expectError:     false,
			expectedCommits: mockCommits,
		},
		{
			name: "commits fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposCommitsByOwnerByRepo,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "nonexistent-repo",
			},
			expectError:    true,
			expectedErrMsg: "failed to list commits",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := ListCommits(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedCommits []*github.RepositoryCommit
			err = json.Unmarshal([]byte(textContent.Text), &returnedCommits)
			require.NoError(t, err)
			assert.Len(t, returnedCommits, len(tc.expectedCommits))
			for i, commit := range returnedCommits {
				assert.Equal(t, *tc.expectedCommits[i].SHA, *commit.SHA)
				assert.Equal(t, *tc.expectedCommits[i].Commit.Message, *commit.Commit.Message)
				assert.Equal(t, *tc.expectedCommits[i].Author.Login, *commit.Author.Login)
				assert.Equal(t, *tc.expectedCommits[i].HTMLURL, *commit.HTMLURL)
			}
		})
	}
}

func Test_CreateOrUpdateFile(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := CreateOrUpdateFile(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "create_or_update_file", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "path")
	assert.Contains(t, tool.InputSchema.Properties, "content")
	assert.Contains(t, tool.InputSchema.Properties, "message")
	assert.Contains(t, tool.InputSchema.Properties, "branch")
	assert.Contains(t, tool.InputSchema.Properties, "sha")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "path", "content", "message", "branch"})

	// Setup mock file content response
	mockFileResponse := &github.RepositoryContentResponse{
		Content: &github.RepositoryContent{
			Name:        github.Ptr("example.md"),
			Path:        github.Ptr("docs/example.md"),
			SHA:         github.Ptr("abc123def456"),
			Size:        github.Ptr(42),
			HTMLURL:     github.Ptr("https://github.com/owner/repo/blob/main/docs/example.md"),
			DownloadURL: github.Ptr("https://raw.githubusercontent.com/owner/repo/main/docs/example.md"),
		},
		Commit: github.Commit{
			SHA:     github.Ptr("def456abc789"),
			Message: github.Ptr("Add example file"),
			Author: &github.CommitAuthor{
				Name:  github.Ptr("Test User"),
				Email: github.Ptr("test@example.com"),
				Date:  &github.Timestamp{Time: time.Now()},
			},
			HTMLURL: github.Ptr("https://github.com/owner/repo/commit/def456abc789"),
		},
	}

	tests := []struct {
		name            string
		mockedClient    *http.Client
		requestArgs     map[string]interface{}
		expectError     bool
		expectedContent *github.RepositoryContentResponse
		expectedErrMsg  string
	}{
		{
			name: "successful file creation",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PutReposContentsByOwnerByRepoByPath,
					expectRequestBody(t, map[string]interface{}{
						"message": "Add example file",
						"content": "IyBFeGFtcGxlCgpUaGlzIGlzIGFuIGV4YW1wbGUgZmlsZS4=", // Base64 encoded content
						"branch":  "main",
					}).andThen(
						mockResponse(t, http.StatusOK, mockFileResponse),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":   "owner",
				"repo":    "repo",
				"path":    "docs/example.md",
				"content": "# Example\n\nThis is an example file.",
				"message": "Add example file",
				"branch":  "main",
			},
			expectError:     false,
			expectedContent: mockFileResponse,
		},
		{
			name: "successful file update with SHA",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PutReposContentsByOwnerByRepoByPath,
					expectRequestBody(t, map[string]interface{}{
						"message": "Update example file",
						"content": "IyBVcGRhdGVkIEV4YW1wbGUKClRoaXMgZmlsZSBoYXMgYmVlbiB1cGRhdGVkLg==", // Base64 encoded content
						"branch":  "main",
						"sha":     "abc123def456",
					}).andThen(
						mockResponse(t, http.StatusOK, mockFileResponse),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":   "owner",
				"repo":    "repo",
				"path":    "docs/example.md",
				"content": "# Updated Example\n\nThis file has been updated.",
				"message": "Update example file",
				"branch":  "main",
				"sha":     "abc123def456",
			},
			expectError:     false,
			expectedContent: mockFileResponse,
		},
		{
			name: "file creation fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.PutReposContentsByOwnerByRepoByPath,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message": "Invalid request"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":   "owner",
				"repo":    "repo",
				"path":    "docs/example.md",
				"content": "#Invalid Content",
				"message": "Invalid request",
				"branch":  "nonexistent-branch",
			},
			expectError:    true,
			expectedErrMsg: "failed to create/update file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := CreateOrUpdateFile(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedContent github.RepositoryContentResponse
			err = json.Unmarshal([]byte(textContent.Text), &returnedContent)
			require.NoError(t, err)

			// Verify content
			assert.Equal(t, *tc.expectedContent.Content.Name, *returnedContent.Content.Name)
			assert.Equal(t, *tc.expectedContent.Content.Path, *returnedContent.Content.Path)
			assert.Equal(t, *tc.expectedContent.Content.SHA, *returnedContent.Content.SHA)

			// Verify commit
			assert.Equal(t, *tc.expectedContent.Commit.SHA, *returnedContent.Commit.SHA)
			assert.Equal(t, *tc.expectedContent.Commit.Message, *returnedContent.Commit.Message)
		})
	}
}

func Test_CreateRepository(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := CreateRepository(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "create_repository", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "name")
	assert.Contains(t, tool.InputSchema.Properties, "description")
	assert.Contains(t, tool.InputSchema.Properties, "private")
	assert.Contains(t, tool.InputSchema.Properties, "autoInit")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"name"})

	// Setup mock repository response
	mockRepo := &github.Repository{
		Name:        github.Ptr("test-repo"),
		Description: github.Ptr("Test repository"),
		Private:     github.Ptr(true),
		HTMLURL:     github.Ptr("https://github.com/testuser/test-repo"),
		CloneURL:    github.Ptr("https://github.com/testuser/test-repo.git"),
		CreatedAt:   &github.Timestamp{Time: time.Now()},
		Owner: &github.User{
			Login: github.Ptr("testuser"),
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedRepo   *github.Repository
		expectedErrMsg string
	}{
		{
			name: "successful repository creation with all parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.EndpointPattern{
						Pattern: "/user/repos",
						Method:  "POST",
					},
					expectRequestBody(t, map[string]interface{}{
						"name":        "test-repo",
						"description": "Test repository",
						"private":     true,
						"auto_init":   true,
					}).andThen(
						mockResponse(t, http.StatusCreated, mockRepo),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"name":        "test-repo",
				"description": "Test repository",
				"private":     true,
				"autoInit":    true,
			},
			expectError:  false,
			expectedRepo: mockRepo,
		},
		{
			name: "successful repository creation with minimal parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.EndpointPattern{
						Pattern: "/user/repos",
						Method:  "POST",
					},
					expectRequestBody(t, map[string]interface{}{
						"name":        "test-repo",
						"auto_init":   false,
						"description": "",
						"private":     false,
					}).andThen(
						mockResponse(t, http.StatusCreated, mockRepo),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"name": "test-repo",
			},
			expectError:  false,
			expectedRepo: mockRepo,
		},
		{
			name: "repository creation fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.EndpointPattern{
						Pattern: "/user/repos",
						Method:  "POST",
					},
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message": "Repository creation failed"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"name": "invalid-repo",
			},
			expectError:    true,
			expectedErrMsg: "failed to create repository",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := CreateRepository(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedRepo github.Repository
			err = json.Unmarshal([]byte(textContent.Text), &returnedRepo)
			assert.NoError(t, err)

			// Verify repository details
			assert.Equal(t, *tc.expectedRepo.Name, *returnedRepo.Name)
			assert.Equal(t, *tc.expectedRepo.Description, *returnedRepo.Description)
			assert.Equal(t, *tc.expectedRepo.Private, *returnedRepo.Private)
			assert.Equal(t, *tc.expectedRepo.HTMLURL, *returnedRepo.HTMLURL)
			assert.Equal(t, *tc.expectedRepo.Owner.Login, *returnedRepo.Owner.Login)
		})
	}
}

func Test_PushFiles(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := PushFiles(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "push_files", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "branch")
	assert.Contains(t, tool.InputSchema.Properties, "files")
	assert.Contains(t, tool.InputSchema.Properties, "message")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo", "branch", "files", "message"})

	// Setup mock objects
	mockRef := &github.Reference{
		Ref: github.Ptr("refs/heads/main"),
		Object: &github.GitObject{
			SHA: github.Ptr("abc123"),
			URL: github.Ptr("https://api.github.com/repos/owner/repo/git/trees/abc123"),
		},
	}

	mockCommit := &github.Commit{
		SHA: github.Ptr("abc123"),
		Tree: &github.Tree{
			SHA: github.Ptr("def456"),
		},
	}

	mockTree := &github.Tree{
		SHA: github.Ptr("ghi789"),
	}

	mockNewCommit := &github.Commit{
		SHA:     github.Ptr("jkl012"),
		Message: github.Ptr("Update multiple files"),
		HTMLURL: github.Ptr("https://github.com/owner/repo/commit/jkl012"),
	}

	mockUpdatedRef := &github.Reference{
		Ref: github.Ptr("refs/heads/main"),
		Object: &github.GitObject{
			SHA: github.Ptr("jkl012"),
			URL: github.Ptr("https://api.github.com/repos/owner/repo/git/trees/jkl012"),
		},
	}

	// Define test cases
	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedRef    *github.Reference
		expectedErrMsg string
	}{
		{
			name: "successful push of multiple files",
			mockedClient: mock.NewMockedHTTPClient(
				// Get branch reference
				mock.WithRequestMatch(
					mock.GetReposGitRefByOwnerByRepoByRef,
					mockRef,
				),
				// Get commit
				mock.WithRequestMatch(
					mock.GetReposGitCommitsByOwnerByRepoByCommitSha,
					mockCommit,
				),
				// Create tree
				mock.WithRequestMatchHandler(
					mock.PostReposGitTreesByOwnerByRepo,
					expectRequestBody(t, map[string]interface{}{
						"base_tree": "def456",
						"tree": []interface{}{
							map[string]interface{}{
								"path":    "README.md",
								"mode":    "100644",
								"type":    "blob",
								"content": "# Updated README\n\nThis is an updated README file.",
							},
							map[string]interface{}{
								"path":    "docs/example.md",
								"mode":    "100644",
								"type":    "blob",
								"content": "# Example\n\nThis is an example file.",
							},
						},
					}).andThen(
						mockResponse(t, http.StatusCreated, mockTree),
					),
				),
				// Create commit
				mock.WithRequestMatchHandler(
					mock.PostReposGitCommitsByOwnerByRepo,
					expectRequestBody(t, map[string]interface{}{
						"message": "Update multiple files",
						"tree":    "ghi789",
						"parents": []interface{}{"abc123"},
					}).andThen(
						mockResponse(t, http.StatusCreated, mockNewCommit),
					),
				),
				// Update reference
				mock.WithRequestMatchHandler(
					mock.PatchReposGitRefsByOwnerByRepoByRef,
					expectRequestBody(t, map[string]interface{}{
						"sha":   "jkl012",
						"force": false,
					}).andThen(
						mockResponse(t, http.StatusOK, mockUpdatedRef),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":  "owner",
				"repo":   "repo",
				"branch": "main",
				"files": []interface{}{
					map[string]interface{}{
						"path":    "README.md",
						"content": "# Updated README\n\nThis is an updated README file.",
					},
					map[string]interface{}{
						"path":    "docs/example.md",
						"content": "# Example\n\nThis is an example file.",
					},
				},
				"message": "Update multiple files",
			},
			expectError: false,
			expectedRef: mockUpdatedRef,
		},
		{
			name:         "fails when files parameter is invalid",
			mockedClient: mock.NewMockedHTTPClient(
			// No requests expected
			),
			requestArgs: map[string]interface{}{
				"owner":   "owner",
				"repo":    "repo",
				"branch":  "main",
				"files":   "invalid-files-parameter", // Not an array
				"message": "Update multiple files",
			},
			expectError:    false, // This returns a tool error, not a Go error
			expectedErrMsg: "files parameter must be an array",
		},
		{
			name: "fails when files contains object without path",
			mockedClient: mock.NewMockedHTTPClient(
				// Get branch reference
				mock.WithRequestMatch(
					mock.GetReposGitRefByOwnerByRepoByRef,
					mockRef,
				),
				// Get commit
				mock.WithRequestMatch(
					mock.GetReposGitCommitsByOwnerByRepoByCommitSha,
					mockCommit,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":  "owner",
				"repo":   "repo",
				"branch": "main",
				"files": []interface{}{
					map[string]interface{}{
						"content": "# Missing path",
					},
				},
				"message": "Update file",
			},
			expectError:    false, // This returns a tool error, not a Go error
			expectedErrMsg: "each file must have a path",
		},
		{
			name: "fails when files contains object without content",
			mockedClient: mock.NewMockedHTTPClient(
				// Get branch reference
				mock.WithRequestMatch(
					mock.GetReposGitRefByOwnerByRepoByRef,
					mockRef,
				),
				// Get commit
				mock.WithRequestMatch(
					mock.GetReposGitCommitsByOwnerByRepoByCommitSha,
					mockCommit,
				),
			),
			requestArgs: map[string]interface{}{
				"owner":  "owner",
				"repo":   "repo",
				"branch": "main",
				"files": []interface{}{
					map[string]interface{}{
						"path": "README.md",
						// Missing content
					},
				},
				"message": "Update file",
			},
			expectError:    false, // This returns a tool error, not a Go error
			expectedErrMsg: "each file must have content",
		},
		{
			name: "fails to get branch reference",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposGitRefByOwnerByRepoByRef,
					mockResponse(t, http.StatusNotFound, nil),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":  "owner",
				"repo":   "repo",
				"branch": "non-existent-branch",
				"files": []interface{}{
					map[string]interface{}{
						"path":    "README.md",
						"content": "# README",
					},
				},
				"message": "Update file",
			},
			expectError:    true,
			expectedErrMsg: "failed to get branch reference",
		},
		{
			name: "fails to get base commit",
			mockedClient: mock.NewMockedHTTPClient(
				// Get branch reference
				mock.WithRequestMatch(
					mock.GetReposGitRefByOwnerByRepoByRef,
					mockRef,
				),
				// Fail to get commit
				mock.WithRequestMatchHandler(
					mock.GetReposGitCommitsByOwnerByRepoByCommitSha,
					mockResponse(t, http.StatusNotFound, nil),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":  "owner",
				"repo":   "repo",
				"branch": "main",
				"files": []interface{}{
					map[string]interface{}{
						"path":    "README.md",
						"content": "# README",
					},
				},
				"message": "Update file",
			},
			expectError:    true,
			expectedErrMsg: "failed to get base commit",
		},
		{
			name: "fails to create tree",
			mockedClient: mock.NewMockedHTTPClient(
				// Get branch reference
				mock.WithRequestMatch(
					mock.GetReposGitRefByOwnerByRepoByRef,
					mockRef,
				),
				// Get commit
				mock.WithRequestMatch(
					mock.GetReposGitCommitsByOwnerByRepoByCommitSha,
					mockCommit,
				),
				// Fail to create tree
				mock.WithRequestMatchHandler(
					mock.PostReposGitTreesByOwnerByRepo,
					mockResponse(t, http.StatusInternalServerError, nil),
				),
			),
			requestArgs: map[string]interface{}{
				"owner":  "owner",
				"repo":   "repo",
				"branch": "main",
				"files": []interface{}{
					map[string]interface{}{
						"path":    "README.md",
						"content": "# README",
					},
				},
				"message": "Update file",
			},
			expectError:    true,
			expectedErrMsg: "failed to create tree",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := PushFiles(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			if tc.expectedErrMsg != "" {
				require.NotNil(t, result)
				textContent := getTextResult(t, result)
				assert.Contains(t, textContent.Text, tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedRef github.Reference
			err = json.Unmarshal([]byte(textContent.Text), &returnedRef)
			require.NoError(t, err)

			assert.Equal(t, *tc.expectedRef.Ref, *returnedRef.Ref)
			assert.Equal(t, *tc.expectedRef.Object.SHA, *returnedRef.Object.SHA)
		})
	}
}

func Test_ListBranches(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := ListBranches(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "list_branches", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "owner")
	assert.Contains(t, tool.InputSchema.Properties, "repo")
	assert.Contains(t, tool.InputSchema.Properties, "page")
	assert.Contains(t, tool.InputSchema.Properties, "perPage")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"owner", "repo"})

	// Setup mock branches for success case
	mockBranches := []*github.Branch{
		{
			Name:   github.Ptr("main"),
			Commit: &github.RepositoryCommit{SHA: github.Ptr("abc123")},
		},
		{
			Name:   github.Ptr("develop"),
			Commit: &github.RepositoryCommit{SHA: github.Ptr("def456")},
		},
	}

	// Test cases
	tests := []struct {
		name          string
		args          map[string]interface{}
		mockResponses []mock.MockBackendOption
		wantErr       bool
		errContains   string
	}{
		{
			name: "success",
			args: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
				"page":  float64(2),
			},
			mockResponses: []mock.MockBackendOption{
				mock.WithRequestMatch(
					mock.GetReposBranchesByOwnerByRepo,
					mockBranches,
				),
			},
			wantErr: false,
		},
		{
			name: "missing owner",
			args: map[string]interface{}{
				"repo": "repo",
			},
			mockResponses: []mock.MockBackendOption{},
			wantErr:       false,
			errContains:   "missing required parameter: owner",
		},
		{
			name: "missing repo",
			args: map[string]interface{}{
				"owner": "owner",
			},
			mockResponses: []mock.MockBackendOption{},
			wantErr:       false,
			errContains:   "missing required parameter: repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock client
			mockClient := github.NewClient(mock.NewMockedHTTPClient(tt.mockResponses...))
			_, handler := ListBranches(stubGetClientFn(mockClient), translations.NullTranslationHelper)

			// Create request
			request := createMCPRequest(tt.args)

			// Call handler
			result, err := handler(context.Background(), request)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			if tt.errContains != "" {
				textContent := getTextResult(t, result)
				assert.Contains(t, textContent.Text, tt.errContains)
				return
			}

			textContent := getTextResult(t, result)
			require.NotEmpty(t, textContent.Text)

			// Verify response
			var branches []*github.Branch
			err = json.Unmarshal([]byte(textContent.Text), &branches)
			require.NoError(t, err)
			assert.Len(t, branches, 2)
			assert.Equal(t, "main", *branches[0].Name)
			assert.Equal(t, "develop", *branches[1].Name)
		})
	}
}
```

---

## `pkg/github/repository_resource.go`

```go
package github

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// GetRepositoryResourceContent defines the resource template and handler for getting repository content.
func GetRepositoryResourceContent(getClient GetClientFn, t translations.TranslationHelperFunc) (mcp.ResourceTemplate, server.ResourceTemplateHandlerFunc) {
	return mcp.NewResourceTemplate(
			"repo://{owner}/{repo}/contents{/path*}", // Resource template
			t("RESOURCE_REPOSITORY_CONTENT_DESCRIPTION", "Repository Content"),
		),
		RepositoryResourceContentsHandler(getClient)
}

// GetRepositoryResourceBranchContent defines the resource template and handler for getting repository content for a branch.
func GetRepositoryResourceBranchContent(getClient GetClientFn, t translations.TranslationHelperFunc) (mcp.ResourceTemplate, server.ResourceTemplateHandlerFunc) {
	return mcp.NewResourceTemplate(
			"repo://{owner}/{repo}/refs/heads/{branch}/contents{/path*}", // Resource template
			t("RESOURCE_REPOSITORY_CONTENT_BRANCH_DESCRIPTION", "Repository Content for specific branch"),
		),
		RepositoryResourceContentsHandler(getClient)
}

// GetRepositoryResourceCommitContent defines the resource template and handler for getting repository content for a commit.
func GetRepositoryResourceCommitContent(getClient GetClientFn, t translations.TranslationHelperFunc) (mcp.ResourceTemplate, server.ResourceTemplateHandlerFunc) {
	return mcp.NewResourceTemplate(
			"repo://{owner}/{repo}/sha/{sha}/contents{/path*}", // Resource template
			t("RESOURCE_REPOSITORY_CONTENT_COMMIT_DESCRIPTION", "Repository Content for specific commit"),
		),
		RepositoryResourceContentsHandler(getClient)
}

// GetRepositoryResourceTagContent defines the resource template and handler for getting repository content for a tag.
func GetRepositoryResourceTagContent(getClient GetClientFn, t translations.TranslationHelperFunc) (mcp.ResourceTemplate, server.ResourceTemplateHandlerFunc) {
	return mcp.NewResourceTemplate(
			"repo://{owner}/{repo}/refs/tags/{tag}/contents{/path*}", // Resource template
			t("RESOURCE_REPOSITORY_CONTENT_TAG_DESCRIPTION", "Repository Content for specific tag"),
		),
		RepositoryResourceContentsHandler(getClient)
}

// GetRepositoryResourcePrContent defines the resource template and handler for getting repository content for a pull request.
func GetRepositoryResourcePrContent(getClient GetClientFn, t translations.TranslationHelperFunc) (mcp.ResourceTemplate, server.ResourceTemplateHandlerFunc) {
	return mcp.NewResourceTemplate(
			"repo://{owner}/{repo}/refs/pull/{prNumber}/head/contents{/path*}", // Resource template
			t("RESOURCE_REPOSITORY_CONTENT_PR_DESCRIPTION", "Repository Content for specific pull request"),
		),
		RepositoryResourceContentsHandler(getClient)
}

// RepositoryResourceContentsHandler returns a handler function for repository content requests.
func RepositoryResourceContentsHandler(getClient GetClientFn) func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	return func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		// the matcher will give []string with one element
		// https://github.com/mark3labs/mcp-go/pull/54
		o, ok := request.Params.Arguments["owner"].([]string)
		if !ok || len(o) == 0 {
			return nil, errors.New("owner is required")
		}
		owner := o[0]

		r, ok := request.Params.Arguments["repo"].([]string)
		if !ok || len(r) == 0 {
			return nil, errors.New("repo is required")
		}
		repo := r[0]

		// path should be a joined list of the path parts
		path := ""
		p, ok := request.Params.Arguments["path"].([]string)
		if ok {
			path = strings.Join(p, "/")
		}

		opts := &github.RepositoryContentGetOptions{}

		sha, ok := request.Params.Arguments["sha"].([]string)
		if ok && len(sha) > 0 {
			opts.Ref = sha[0]
		}

		branch, ok := request.Params.Arguments["branch"].([]string)
		if ok && len(branch) > 0 {
			opts.Ref = "refs/heads/" + branch[0]
		}

		tag, ok := request.Params.Arguments["tag"].([]string)
		if ok && len(tag) > 0 {
			opts.Ref = "refs/tags/" + tag[0]
		}
		prNumber, ok := request.Params.Arguments["prNumber"].([]string)
		if ok && len(prNumber) > 0 {
			opts.Ref = "refs/pull/" + prNumber[0] + "/head"
		}

		client, err := getClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get GitHub client: %w", err)
		}
		fileContent, directoryContent, _, err := client.Repositories.GetContents(ctx, owner, repo, path, opts)
		if err != nil {
			return nil, err
		}

		if directoryContent != nil {
			var resources []mcp.ResourceContents
			for _, entry := range directoryContent {
				mimeType := "text/directory"
				if entry.GetType() == "file" {
					// this is system dependent, and a best guess
					ext := filepath.Ext(entry.GetName())
					mimeType = mime.TypeByExtension(ext)
					if ext == ".md" {
						mimeType = "text/markdown"
					}
				}
				resources = append(resources, mcp.TextResourceContents{
					URI:      entry.GetHTMLURL(),
					MIMEType: mimeType,
					Text:     entry.GetName(),
				})

			}
			return resources, nil

		}
		if fileContent != nil {
			if fileContent.Content != nil {
				// download the file content from fileContent.GetDownloadURL() and use the content-type header to determine the MIME type
				// and return the content as a blob unless it is a text file, where you can return the content as text
				req, err := http.NewRequest("GET", fileContent.GetDownloadURL(), nil)
				if err != nil {
					return nil, fmt.Errorf("failed to create request: %w", err)
				}

				resp, err := client.Client().Do(req)
				if err != nil {
					return nil, fmt.Errorf("failed to send request: %w", err)
				}
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusOK {
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						return nil, fmt.Errorf("failed to read response body: %w", err)
					}
					return nil, fmt.Errorf("failed to fetch file content: %s", string(body))
				}

				ext := filepath.Ext(fileContent.GetName())
				mimeType := resp.Header.Get("Content-Type")
				if ext == ".md" {
					mimeType = "text/markdown"
				} else if mimeType == "" {
					// backstop to the file extension if the content type is not set
					mimeType = mime.TypeByExtension(filepath.Ext(fileContent.GetName()))
				}

				// if the content is a string, return it as text
				if strings.HasPrefix(mimeType, "text") {
					content, err := io.ReadAll(resp.Body)
					if err != nil {
						return nil, fmt.Errorf("failed to parse the response body: %w", err)
					}

					return []mcp.ResourceContents{
						mcp.TextResourceContents{
							URI:      request.Params.URI,
							MIMEType: mimeType,
							Text:     string(content),
						},
					}, nil
				}
				// otherwise, read the content and encode it as base64
				decodedContent, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to parse the response body: %w", err)
				}

				return []mcp.ResourceContents{
					mcp.BlobResourceContents{
						URI:      request.Params.URI,
						MIMEType: mimeType,
						Blob:     base64.StdEncoding.EncodeToString(decodedContent), // Encode content as Base64
					},
				}, nil
			}
		}

		return nil, errors.New("no repository resource content found")
	}
}
```

---

## `pkg/github/repository_resource_test.go`

```go
package github

import (
	"context"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/require"
)

var GetRawReposContentsByOwnerByRepoByPath mock.EndpointPattern = mock.EndpointPattern{
	Pattern: "/{owner}/{repo}/main/{path:.+}",
	Method:  "GET",
}

func Test_repositoryResourceContentsHandler(t *testing.T) {
	mockDirContent := []*github.RepositoryContent{
		{
			Type:        github.Ptr("file"),
			Name:        github.Ptr("README.md"),
			Path:        github.Ptr("README.md"),
			SHA:         github.Ptr("abc123"),
			Size:        github.Ptr(42),
			HTMLURL:     github.Ptr("https://github.com/owner/repo/blob/main/README.md"),
			DownloadURL: github.Ptr("https://raw.githubusercontent.com/owner/repo/main/README.md"),
		},
		{
			Type:        github.Ptr("dir"),
			Name:        github.Ptr("src"),
			Path:        github.Ptr("src"),
			SHA:         github.Ptr("def456"),
			HTMLURL:     github.Ptr("https://github.com/owner/repo/tree/main/src"),
			DownloadURL: github.Ptr("https://raw.githubusercontent.com/owner/repo/main/src"),
		},
	}
	expectedDirContent := []mcp.TextResourceContents{
		{
			URI:      "https://github.com/owner/repo/blob/main/README.md",
			MIMEType: "text/markdown",
			Text:     "README.md",
		},
		{
			URI:      "https://github.com/owner/repo/tree/main/src",
			MIMEType: "text/directory",
			Text:     "src",
		},
	}

	mockTextContent := &github.RepositoryContent{
		Type:        github.Ptr("file"),
		Name:        github.Ptr("README.md"),
		Path:        github.Ptr("README.md"),
		Content:     github.Ptr("# Test Repository\n\nThis is a test repository."),
		SHA:         github.Ptr("abc123"),
		Size:        github.Ptr(42),
		HTMLURL:     github.Ptr("https://github.com/owner/repo/blob/main/README.md"),
		DownloadURL: github.Ptr("https://raw.githubusercontent.com/owner/repo/main/README.md"),
	}

	mockFileContent := &github.RepositoryContent{
		Type:        github.Ptr("file"),
		Name:        github.Ptr("data.png"),
		Path:        github.Ptr("data.png"),
		Content:     github.Ptr("IyBUZXN0IFJlcG9zaXRvcnkKClRoaXMgaXMgYSB0ZXN0IHJlcG9zaXRvcnku"), // Base64 encoded "# Test Repository\n\nThis is a test repository."
		SHA:         github.Ptr("abc123"),
		Size:        github.Ptr(42),
		HTMLURL:     github.Ptr("https://github.com/owner/repo/blob/main/data.png"),
		DownloadURL: github.Ptr("https://raw.githubusercontent.com/owner/repo/main/data.png"),
	}

	expectedFileContent := []mcp.BlobResourceContents{
		{
			Blob:     "IyBUZXN0IFJlcG9zaXRvcnkKClRoaXMgaXMgYSB0ZXN0IHJlcG9zaXRvcnku",
			MIMEType: "image/png",
			URI:      "",
		},
	}

	expectedTextContent := []mcp.TextResourceContents{
		{
			Text:     "# Test Repository\n\nThis is a test repository.",
			MIMEType: "text/markdown",
			URI:      "",
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]any
		expectError    string
		expectedResult any
		expectedErrMsg string
	}{
		{
			name: "missing owner",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposContentsByOwnerByRepoByPath,
					mockFileContent,
				),
			),
			requestArgs: map[string]any{},
			expectError: "owner is required",
		},
		{
			name: "missing repo",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposContentsByOwnerByRepoByPath,
					mockFileContent,
				),
			),
			requestArgs: map[string]any{
				"owner": []string{"owner"},
			},
			expectError: "repo is required",
		},
		{
			name: "successful blob content fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposContentsByOwnerByRepoByPath,
					mockFileContent,
				),
				mock.WithRequestMatchHandler(
					GetRawReposContentsByOwnerByRepoByPath,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", "image/png")
						// as this is given as a png, it will return the content as a blob
						_, err := w.Write([]byte("# Test Repository\n\nThis is a test repository."))
						require.NoError(t, err)
					}),
				),
			),
			requestArgs: map[string]any{
				"owner":  []string{"owner"},
				"repo":   []string{"repo"},
				"path":   []string{"data.png"},
				"branch": []string{"main"},
			},
			expectedResult: expectedFileContent,
		},
		{
			name: "successful text content fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposContentsByOwnerByRepoByPath,
					mockTextContent,
				),
				mock.WithRequestMatch(
					GetRawReposContentsByOwnerByRepoByPath,
					[]byte("# Test Repository\n\nThis is a test repository."),
				),
			),
			requestArgs: map[string]any{
				"owner":  []string{"owner"},
				"repo":   []string{"repo"},
				"path":   []string{"README.md"},
				"branch": []string{"main"},
			},
			expectedResult: expectedTextContent,
		},
		{
			name: "successful directory content fetch",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposContentsByOwnerByRepoByPath,
					mockDirContent,
				),
			),
			requestArgs: map[string]any{
				"owner": []string{"owner"},
				"repo":  []string{"repo"},
				"path":  []string{"src"},
			},
			expectedResult: expectedDirContent,
		},
		{
			name: "no data",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposContentsByOwnerByRepoByPath,
				),
			),
			requestArgs: map[string]any{
				"owner": []string{"owner"},
				"repo":  []string{"repo"},
				"path":  []string{"src"},
			},
			expectedResult: nil,
			expectError:    "no repository resource content found",
		},
		{
			name: "empty data",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetReposContentsByOwnerByRepoByPath,
					[]*github.RepositoryContent{},
				),
			),
			requestArgs: map[string]any{
				"owner": []string{"owner"},
				"repo":  []string{"repo"},
				"path":  []string{"src"},
			},
			expectedResult: nil,
		},
		{
			name: "content fetch fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetReposContentsByOwnerByRepoByPath,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "Not Found"}`))
					}),
				),
			),
			requestArgs: map[string]any{
				"owner":  []string{"owner"},
				"repo":   []string{"repo"},
				"path":   []string{"nonexistent.md"},
				"branch": []string{"main"},
			},
			expectError: "404 Not Found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := github.NewClient(tc.mockedClient)
			handler := RepositoryResourceContentsHandler((stubGetClientFn(client)))

			request := mcp.ReadResourceRequest{
				Params: struct {
					URI       string         `json:"uri"`
					Arguments map[string]any `json:"arguments,omitempty"`
				}{
					Arguments: tc.requestArgs,
				},
			}

			resp, err := handler(context.TODO(), request)

			if tc.expectError != "" {
				require.ErrorContains(t, err, tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			require.ElementsMatch(t, resp, tc.expectedResult)
		})
	}
}

func Test_GetRepositoryResourceContent(t *testing.T) {
	tmpl, _ := GetRepositoryResourceContent(nil, translations.NullTranslationHelper)
	require.Equal(t, "repo://{owner}/{repo}/contents{/path*}", tmpl.URITemplate.Raw())
}

func Test_GetRepositoryResourceBranchContent(t *testing.T) {
	tmpl, _ := GetRepositoryResourceBranchContent(nil, translations.NullTranslationHelper)
	require.Equal(t, "repo://{owner}/{repo}/refs/heads/{branch}/contents{/path*}", tmpl.URITemplate.Raw())
}
func Test_GetRepositoryResourceCommitContent(t *testing.T) {
	tmpl, _ := GetRepositoryResourceCommitContent(nil, translations.NullTranslationHelper)
	require.Equal(t, "repo://{owner}/{repo}/sha/{sha}/contents{/path*}", tmpl.URITemplate.Raw())
}

func Test_GetRepositoryResourceTagContent(t *testing.T) {
	tmpl, _ := GetRepositoryResourceTagContent(nil, translations.NullTranslationHelper)
	require.Equal(t, "repo://{owner}/{repo}/refs/tags/{tag}/contents{/path*}", tmpl.URITemplate.Raw())
}

func Test_GetRepositoryResourcePrContent(t *testing.T) {
	tmpl, _ := GetRepositoryResourcePrContent(nil, translations.NullTranslationHelper)
	require.Equal(t, "repo://{owner}/{repo}/refs/pull/{prNumber}/head/contents{/path*}", tmpl.URITemplate.Raw())
}
```

---

## `pkg/github/resources.go`

```go
package github

import (
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/mark3labs/mcp-go/server"
)

func RegisterResources(s *server.MCPServer, getClient GetClientFn, t translations.TranslationHelperFunc) {
	s.AddResourceTemplate(GetRepositoryResourceContent(getClient, t))
	s.AddResourceTemplate(GetRepositoryResourceBranchContent(getClient, t))
	s.AddResourceTemplate(GetRepositoryResourceCommitContent(getClient, t))
	s.AddResourceTemplate(GetRepositoryResourceTagContent(getClient, t))
	s.AddResourceTemplate(GetRepositoryResourcePrContent(getClient, t))
}
```

---

## `pkg/github/search.go`

```go
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// SearchRepositories creates a tool to search for GitHub repositories.
func SearchRepositories(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("search_repositories",
			mcp.WithDescription(t("TOOL_SEARCH_REPOSITORIES_DESCRIPTION", "Search for GitHub repositories")),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Search query"),
			),
			WithPagination(),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			query, err := requiredParam[string](request, "query")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pagination, err := OptionalPaginationParams(request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.SearchOptions{
				ListOptions: github.ListOptions{
					Page:    pagination.page,
					PerPage: pagination.perPage,
				},
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}
			result, resp, err := client.Search.Repositories(ctx, query, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to search repositories: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != 200 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to search repositories: %s", string(body))), nil
			}

			r, err := json.Marshal(result)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// SearchCode creates a tool to search for code across GitHub repositories.
func SearchCode(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("search_code",
			mcp.WithDescription(t("TOOL_SEARCH_CODE_DESCRIPTION", "Search for code across GitHub repositories")),
			mcp.WithString("q",
				mcp.Required(),
				mcp.Description("Search query using GitHub code search syntax"),
			),
			mcp.WithString("sort",
				mcp.Description("Sort field ('indexed' only)"),
			),
			mcp.WithString("order",
				mcp.Description("Sort order ('asc' or 'desc')"),
				mcp.Enum("asc", "desc"),
			),
			WithPagination(),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			query, err := requiredParam[string](request, "q")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			sort, err := OptionalParam[string](request, "sort")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			order, err := OptionalParam[string](request, "order")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pagination, err := OptionalPaginationParams(request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.SearchOptions{
				Sort:  sort,
				Order: order,
				ListOptions: github.ListOptions{
					PerPage: pagination.perPage,
					Page:    pagination.page,
				},
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}

			result, resp, err := client.Search.Code(ctx, query, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to search code: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != 200 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to search code: %s", string(body))), nil
			}

			r, err := json.Marshal(result)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}

// SearchUsers creates a tool to search for GitHub users.
func SearchUsers(getClient GetClientFn, t translations.TranslationHelperFunc) (tool mcp.Tool, handler server.ToolHandlerFunc) {
	return mcp.NewTool("search_users",
			mcp.WithDescription(t("TOOL_SEARCH_USERS_DESCRIPTION", "Search for GitHub users")),
			mcp.WithString("q",
				mcp.Required(),
				mcp.Description("Search query using GitHub users search syntax"),
			),
			mcp.WithString("sort",
				mcp.Description("Sort field (followers, repositories, joined)"),
				mcp.Enum("followers", "repositories", "joined"),
			),
			mcp.WithString("order",
				mcp.Description("Sort order ('asc' or 'desc')"),
				mcp.Enum("asc", "desc"),
			),
			WithPagination(),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			query, err := requiredParam[string](request, "q")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			sort, err := OptionalParam[string](request, "sort")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			order, err := OptionalParam[string](request, "order")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			pagination, err := OptionalPaginationParams(request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			opts := &github.SearchOptions{
				Sort:  sort,
				Order: order,
				ListOptions: github.ListOptions{
					PerPage: pagination.perPage,
					Page:    pagination.page,
				},
			}

			client, err := getClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get GitHub client: %w", err)
			}

			result, resp, err := client.Search.Users(ctx, query, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to search users: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != 200 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				return mcp.NewToolResultError(fmt.Sprintf("failed to search users: %s", string(body))), nil
			}

			r, err := json.Marshal(result)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response: %w", err)
			}

			return mcp.NewToolResultText(string(r)), nil
		}
}
```

---

## `pkg/github/search_test.go`

```go
package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SearchRepositories(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := SearchRepositories(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "search_repositories", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "query")
	assert.Contains(t, tool.InputSchema.Properties, "page")
	assert.Contains(t, tool.InputSchema.Properties, "perPage")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"query"})

	// Setup mock search results
	mockSearchResult := &github.RepositoriesSearchResult{
		Total:             github.Ptr(2),
		IncompleteResults: github.Ptr(false),
		Repositories: []*github.Repository{
			{
				ID:              github.Ptr(int64(12345)),
				Name:            github.Ptr("repo-1"),
				FullName:        github.Ptr("owner/repo-1"),
				HTMLURL:         github.Ptr("https://github.com/owner/repo-1"),
				Description:     github.Ptr("Test repository 1"),
				StargazersCount: github.Ptr(100),
			},
			{
				ID:              github.Ptr(int64(67890)),
				Name:            github.Ptr("repo-2"),
				FullName:        github.Ptr("owner/repo-2"),
				HTMLURL:         github.Ptr("https://github.com/owner/repo-2"),
				Description:     github.Ptr("Test repository 2"),
				StargazersCount: github.Ptr(50),
			},
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedResult *github.RepositoriesSearchResult
		expectedErrMsg string
	}{
		{
			name: "successful repository search",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchRepositories,
					expectQueryParams(t, map[string]string{
						"q":        "golang test",
						"page":     "2",
						"per_page": "10",
					}).andThen(
						mockResponse(t, http.StatusOK, mockSearchResult),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"query":   "golang test",
				"page":    float64(2),
				"perPage": float64(10),
			},
			expectError:    false,
			expectedResult: mockSearchResult,
		},
		{
			name: "repository search with default pagination",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchRepositories,
					expectQueryParams(t, map[string]string{
						"q":        "golang test",
						"page":     "1",
						"per_page": "30",
					}).andThen(
						mockResponse(t, http.StatusOK, mockSearchResult),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"query": "golang test",
			},
			expectError:    false,
			expectedResult: mockSearchResult,
		},
		{
			name: "search fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchRepositories,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"message": "Invalid query"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"query": "invalid:query",
			},
			expectError:    true,
			expectedErrMsg: "failed to search repositories",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := SearchRepositories(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedResult github.RepositoriesSearchResult
			err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedResult.Total, *returnedResult.Total)
			assert.Equal(t, *tc.expectedResult.IncompleteResults, *returnedResult.IncompleteResults)
			assert.Len(t, returnedResult.Repositories, len(tc.expectedResult.Repositories))
			for i, repo := range returnedResult.Repositories {
				assert.Equal(t, *tc.expectedResult.Repositories[i].ID, *repo.ID)
				assert.Equal(t, *tc.expectedResult.Repositories[i].Name, *repo.Name)
				assert.Equal(t, *tc.expectedResult.Repositories[i].FullName, *repo.FullName)
				assert.Equal(t, *tc.expectedResult.Repositories[i].HTMLURL, *repo.HTMLURL)
			}

		})
	}
}

func Test_SearchCode(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := SearchCode(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "search_code", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "q")
	assert.Contains(t, tool.InputSchema.Properties, "sort")
	assert.Contains(t, tool.InputSchema.Properties, "order")
	assert.Contains(t, tool.InputSchema.Properties, "perPage")
	assert.Contains(t, tool.InputSchema.Properties, "page")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"q"})

	// Setup mock search results
	mockSearchResult := &github.CodeSearchResult{
		Total:             github.Ptr(2),
		IncompleteResults: github.Ptr(false),
		CodeResults: []*github.CodeResult{
			{
				Name:       github.Ptr("file1.go"),
				Path:       github.Ptr("path/to/file1.go"),
				SHA:        github.Ptr("abc123def456"),
				HTMLURL:    github.Ptr("https://github.com/owner/repo/blob/main/path/to/file1.go"),
				Repository: &github.Repository{Name: github.Ptr("repo"), FullName: github.Ptr("owner/repo")},
			},
			{
				Name:       github.Ptr("file2.go"),
				Path:       github.Ptr("path/to/file2.go"),
				SHA:        github.Ptr("def456abc123"),
				HTMLURL:    github.Ptr("https://github.com/owner/repo/blob/main/path/to/file2.go"),
				Repository: &github.Repository{Name: github.Ptr("repo"), FullName: github.Ptr("owner/repo")},
			},
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedResult *github.CodeSearchResult
		expectedErrMsg string
	}{
		{
			name: "successful code search with all parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchCode,
					expectQueryParams(t, map[string]string{
						"q":        "fmt.Println language:go",
						"sort":     "indexed",
						"order":    "desc",
						"page":     "1",
						"per_page": "30",
					}).andThen(
						mockResponse(t, http.StatusOK, mockSearchResult),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"q":       "fmt.Println language:go",
				"sort":    "indexed",
				"order":   "desc",
				"page":    float64(1),
				"perPage": float64(30),
			},
			expectError:    false,
			expectedResult: mockSearchResult,
		},
		{
			name: "code search with minimal parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchCode,
					expectQueryParams(t, map[string]string{
						"q":        "fmt.Println language:go",
						"page":     "1",
						"per_page": "30",
					}).andThen(
						mockResponse(t, http.StatusOK, mockSearchResult),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"q": "fmt.Println language:go",
			},
			expectError:    false,
			expectedResult: mockSearchResult,
		},
		{
			name: "search code fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchCode,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"message": "Validation Failed"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"q": "invalid:query",
			},
			expectError:    true,
			expectedErrMsg: "failed to search code",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := SearchCode(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedResult github.CodeSearchResult
			err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedResult.Total, *returnedResult.Total)
			assert.Equal(t, *tc.expectedResult.IncompleteResults, *returnedResult.IncompleteResults)
			assert.Len(t, returnedResult.CodeResults, len(tc.expectedResult.CodeResults))
			for i, code := range returnedResult.CodeResults {
				assert.Equal(t, *tc.expectedResult.CodeResults[i].Name, *code.Name)
				assert.Equal(t, *tc.expectedResult.CodeResults[i].Path, *code.Path)
				assert.Equal(t, *tc.expectedResult.CodeResults[i].SHA, *code.SHA)
				assert.Equal(t, *tc.expectedResult.CodeResults[i].HTMLURL, *code.HTMLURL)
				assert.Equal(t, *tc.expectedResult.CodeResults[i].Repository.FullName, *code.Repository.FullName)
			}
		})
	}
}

func Test_SearchUsers(t *testing.T) {
	// Verify tool definition once
	mockClient := github.NewClient(nil)
	tool, _ := SearchUsers(stubGetClientFn(mockClient), translations.NullTranslationHelper)

	assert.Equal(t, "search_users", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "q")
	assert.Contains(t, tool.InputSchema.Properties, "sort")
	assert.Contains(t, tool.InputSchema.Properties, "order")
	assert.Contains(t, tool.InputSchema.Properties, "perPage")
	assert.Contains(t, tool.InputSchema.Properties, "page")
	assert.ElementsMatch(t, tool.InputSchema.Required, []string{"q"})

	// Setup mock search results
	mockSearchResult := &github.UsersSearchResult{
		Total:             github.Ptr(2),
		IncompleteResults: github.Ptr(false),
		Users: []*github.User{
			{
				Login:     github.Ptr("user1"),
				ID:        github.Ptr(int64(1001)),
				HTMLURL:   github.Ptr("https://github.com/user1"),
				AvatarURL: github.Ptr("https://avatars.githubusercontent.com/u/1001"),
				Type:      github.Ptr("User"),
				Followers: github.Ptr(100),
				Following: github.Ptr(50),
			},
			{
				Login:     github.Ptr("user2"),
				ID:        github.Ptr(int64(1002)),
				HTMLURL:   github.Ptr("https://github.com/user2"),
				AvatarURL: github.Ptr("https://avatars.githubusercontent.com/u/1002"),
				Type:      github.Ptr("User"),
				Followers: github.Ptr(200),
				Following: github.Ptr(75),
			},
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedResult *github.UsersSearchResult
		expectedErrMsg string
	}{
		{
			name: "successful users search with all parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchUsers,
					expectQueryParams(t, map[string]string{
						"q":        "location:finland language:go",
						"sort":     "followers",
						"order":    "desc",
						"page":     "1",
						"per_page": "30",
					}).andThen(
						mockResponse(t, http.StatusOK, mockSearchResult),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"q":       "location:finland language:go",
				"sort":    "followers",
				"order":   "desc",
				"page":    float64(1),
				"perPage": float64(30),
			},
			expectError:    false,
			expectedResult: mockSearchResult,
		},
		{
			name: "users search with minimal parameters",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchUsers,
					expectQueryParams(t, map[string]string{
						"q":        "location:finland language:go",
						"page":     "1",
						"per_page": "30",
					}).andThen(
						mockResponse(t, http.StatusOK, mockSearchResult),
					),
				),
			),
			requestArgs: map[string]interface{}{
				"q": "location:finland language:go",
			},
			expectError:    false,
			expectedResult: mockSearchResult,
		},
		{
			name: "search users fails",
			mockedClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetSearchUsers,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"message": "Validation Failed"}`))
					}),
				),
			),
			requestArgs: map[string]interface{}{
				"q": "invalid:query",
			},
			expectError:    true,
			expectedErrMsg: "failed to search users",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			_, handler := SearchUsers(stubGetClientFn(client), translations.NullTranslationHelper)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler
			result, err := handler(context.Background(), request)

			// Verify results
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Parse the result and get the text content if no error
			require.NotNil(t, result)

			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedResult github.UsersSearchResult
			err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
			require.NoError(t, err)
			assert.Equal(t, *tc.expectedResult.Total, *returnedResult.Total)
			assert.Equal(t, *tc.expectedResult.IncompleteResults, *returnedResult.IncompleteResults)
			assert.Len(t, returnedResult.Users, len(tc.expectedResult.Users))
			for i, user := range returnedResult.Users {
				assert.Equal(t, *tc.expectedResult.Users[i].Login, *user.Login)
				assert.Equal(t, *tc.expectedResult.Users[i].ID, *user.ID)
				assert.Equal(t, *tc.expectedResult.Users[i].HTMLURL, *user.HTMLURL)
				assert.Equal(t, *tc.expectedResult.Users[i].AvatarURL, *user.AvatarURL)
				assert.Equal(t, *tc.expectedResult.Users[i].Type, *user.Type)
				assert.Equal(t, *tc.expectedResult.Users[i].Followers, *user.Followers)
			}
		})
	}
}
```

---

## `pkg/github/server.go`

```go
package github

import (
	"errors"
	"fmt"

	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// NewServer creates a new GitHub MCP server with the specified GH client and logger.

func NewServer(version string, opts ...server.ServerOption) *server.MCPServer {
	// Add default options
	defaultOpts := []server.ServerOption{
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithLogging(),
	}
	opts = append(defaultOpts, opts...)

	// Create a new MCP server
	s := server.NewMCPServer(
		"github-mcp-server",
		version,
		opts...,
	)
	return s
}

// OptionalParamOK is a helper function that can be used to fetch a requested parameter from the request.
// It returns the value, a boolean indicating if the parameter was present, and an error if the type is wrong.
func OptionalParamOK[T any](r mcp.CallToolRequest, p string) (value T, ok bool, err error) {
	// Check if the parameter is present in the request
	val, exists := r.Params.Arguments[p]
	if !exists {
		// Not present, return zero value, false, no error
		return
	}

	// Check if the parameter is of the expected type
	value, ok = val.(T)
	if !ok {
		// Present but wrong type
		err = fmt.Errorf("parameter %s is not of type %T, is %T", p, value, val)
		ok = true // Set ok to true because the parameter *was* present, even if wrong type
		return
	}

	// Present and correct type
	ok = true
	return
}

// isAcceptedError checks if the error is an accepted error.
func isAcceptedError(err error) bool {
	var acceptedError *github.AcceptedError
	return errors.As(err, &acceptedError)
}

// requiredParam is a helper function that can be used to fetch a requested parameter from the request.
// It does the following checks:
// 1. Checks if the parameter is present in the request.
// 2. Checks if the parameter is of the expected type.
// 3. Checks if the parameter is not empty, i.e: non-zero value
func requiredParam[T comparable](r mcp.CallToolRequest, p string) (T, error) {
	var zero T

	// Check if the parameter is present in the request
	if _, ok := r.Params.Arguments[p]; !ok {
		return zero, fmt.Errorf("missing required parameter: %s", p)
	}

	// Check if the parameter is of the expected type
	if _, ok := r.Params.Arguments[p].(T); !ok {
		return zero, fmt.Errorf("parameter %s is not of type %T", p, zero)
	}

	if r.Params.Arguments[p].(T) == zero {
		return zero, fmt.Errorf("missing required parameter: %s", p)

	}

	return r.Params.Arguments[p].(T), nil
}

// RequiredInt is a helper function that can be used to fetch a requested parameter from the request.
// It does the following checks:
// 1. Checks if the parameter is present in the request.
// 2. Checks if the parameter is of the expected type.
// 3. Checks if the parameter is not empty, i.e: non-zero value
func RequiredInt(r mcp.CallToolRequest, p string) (int, error) {
	v, err := requiredParam[float64](r, p)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

// OptionalParam is a helper function that can be used to fetch a requested parameter from the request.
// It does the following checks:
// 1. Checks if the parameter is present in the request, if not, it returns its zero-value
// 2. If it is present, it checks if the parameter is of the expected type and returns it
func OptionalParam[T any](r mcp.CallToolRequest, p string) (T, error) {
	var zero T

	// Check if the parameter is present in the request
	if _, ok := r.Params.Arguments[p]; !ok {
		return zero, nil
	}

	// Check if the parameter is of the expected type
	if _, ok := r.Params.Arguments[p].(T); !ok {
		return zero, fmt.Errorf("parameter %s is not of type %T, is %T", p, zero, r.Params.Arguments[p])
	}

	return r.Params.Arguments[p].(T), nil
}

// OptionalIntParam is a helper function that can be used to fetch a requested parameter from the request.
// It does the following checks:
// 1. Checks if the parameter is present in the request, if not, it returns its zero-value
// 2. If it is present, it checks if the parameter is of the expected type and returns it
func OptionalIntParam(r mcp.CallToolRequest, p string) (int, error) {
	v, err := OptionalParam[float64](r, p)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

// OptionalIntParamWithDefault is a helper function that can be used to fetch a requested parameter from the request
// similar to optionalIntParam, but it also takes a default value.
func OptionalIntParamWithDefault(r mcp.CallToolRequest, p string, d int) (int, error) {
	v, err := OptionalIntParam(r, p)
	if err != nil {
		return 0, err
	}
	if v == 0 {
		return d, nil
	}
	return v, nil
}

// OptionalStringArrayParam is a helper function that can be used to fetch a requested parameter from the request.
// It does the following checks:
// 1. Checks if the parameter is present in the request, if not, it returns its zero-value
// 2. If it is present, iterates the elements and checks each is a string
func OptionalStringArrayParam(r mcp.CallToolRequest, p string) ([]string, error) {
	// Check if the parameter is present in the request
	if _, ok := r.Params.Arguments[p]; !ok {
		return []string{}, nil
	}

	switch v := r.Params.Arguments[p].(type) {
	case nil:
		return []string{}, nil
	case []string:
		return v, nil
	case []any:
		strSlice := make([]string, len(v))
		for i, v := range v {
			s, ok := v.(string)
			if !ok {
				return []string{}, fmt.Errorf("parameter %s is not of type string, is %T", p, v)
			}
			strSlice[i] = s
		}
		return strSlice, nil
	default:
		return []string{}, fmt.Errorf("parameter %s could not be coerced to []string, is %T", p, r.Params.Arguments[p])
	}
}

// WithPagination returns a ToolOption that adds "page" and "perPage" parameters to the tool.
// The "page" parameter is optional, min 1. The "perPage" parameter is optional, min 1, max 100.
func WithPagination() mcp.ToolOption {
	return func(tool *mcp.Tool) {
		mcp.WithNumber("page",
			mcp.Description("Page number for pagination (min 1)"),
			mcp.Min(1),
		)(tool)

		mcp.WithNumber("perPage",
			mcp.Description("Results per page for pagination (min 1, max 100)"),
			mcp.Min(1),
			mcp.Max(100),
		)(tool)
	}
}

type PaginationParams struct {
	page    int
	perPage int
}

// OptionalPaginationParams returns the "page" and "perPage" parameters from the request,
// or their default values if not present, "page" default is 1, "perPage" default is 30.
// In future, we may want to make the default values configurable, or even have this
// function returned from `withPagination`, where the defaults are provided alongside
// the min/max values.
func OptionalPaginationParams(r mcp.CallToolRequest) (PaginationParams, error) {
	page, err := OptionalIntParamWithDefault(r, "page", 1)
	if err != nil {
		return PaginationParams{}, err
	}
	perPage, err := OptionalIntParamWithDefault(r, "perPage", 30)
	if err != nil {
		return PaginationParams{}, err
	}
	return PaginationParams{
		page:    page,
		perPage: perPage,
	}, nil
}
```

---

## `pkg/github/server_test.go`

```go
package github

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-github/v69/github"
	"github.com/stretchr/testify/assert"
)

func stubGetClientFn(client *github.Client) GetClientFn {
	return func(_ context.Context) (*github.Client, error) {
		return client, nil
	}
}

func Test_IsAcceptedError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectAccepted bool
	}{
		{
			name:           "github AcceptedError",
			err:            &github.AcceptedError{},
			expectAccepted: true,
		},
		{
			name:           "regular error",
			err:            fmt.Errorf("some other error"),
			expectAccepted: false,
		},
		{
			name:           "nil error",
			err:            nil,
			expectAccepted: false,
		},
		{
			name:           "wrapped AcceptedError",
			err:            fmt.Errorf("wrapped: %w", &github.AcceptedError{}),
			expectAccepted: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isAcceptedError(tc.err)
			assert.Equal(t, tc.expectAccepted, result)
		})
	}
}

func Test_RequiredStringParam(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		paramName   string
		expected    string
		expectError bool
	}{
		{
			name:        "valid string parameter",
			params:      map[string]interface{}{"name": "test-value"},
			paramName:   "name",
			expected:    "test-value",
			expectError: false,
		},
		{
			name:        "missing parameter",
			params:      map[string]interface{}{},
			paramName:   "name",
			expected:    "",
			expectError: true,
		},
		{
			name:        "empty string parameter",
			params:      map[string]interface{}{"name": ""},
			paramName:   "name",
			expected:    "",
			expectError: true,
		},
		{
			name:        "wrong type parameter",
			params:      map[string]interface{}{"name": 123},
			paramName:   "name",
			expected:    "",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := createMCPRequest(tc.params)
			result, err := requiredParam[string](request, tc.paramName)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func Test_OptionalStringParam(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		paramName   string
		expected    string
		expectError bool
	}{
		{
			name:        "valid string parameter",
			params:      map[string]interface{}{"name": "test-value"},
			paramName:   "name",
			expected:    "test-value",
			expectError: false,
		},
		{
			name:        "missing parameter",
			params:      map[string]interface{}{},
			paramName:   "name",
			expected:    "",
			expectError: false,
		},
		{
			name:        "empty string parameter",
			params:      map[string]interface{}{"name": ""},
			paramName:   "name",
			expected:    "",
			expectError: false,
		},
		{
			name:        "wrong type parameter",
			params:      map[string]interface{}{"name": 123},
			paramName:   "name",
			expected:    "",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := createMCPRequest(tc.params)
			result, err := OptionalParam[string](request, tc.paramName)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func Test_RequiredNumberParam(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		paramName   string
		expected    int
		expectError bool
	}{
		{
			name:        "valid number parameter",
			params:      map[string]interface{}{"count": float64(42)},
			paramName:   "count",
			expected:    42,
			expectError: false,
		},
		{
			name:        "missing parameter",
			params:      map[string]interface{}{},
			paramName:   "count",
			expected:    0,
			expectError: true,
		},
		{
			name:        "wrong type parameter",
			params:      map[string]interface{}{"count": "not-a-number"},
			paramName:   "count",
			expected:    0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := createMCPRequest(tc.params)
			result, err := RequiredInt(request, tc.paramName)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func Test_OptionalNumberParam(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		paramName   string
		expected    int
		expectError bool
	}{
		{
			name:        "valid number parameter",
			params:      map[string]interface{}{"count": float64(42)},
			paramName:   "count",
			expected:    42,
			expectError: false,
		},
		{
			name:        "missing parameter",
			params:      map[string]interface{}{},
			paramName:   "count",
			expected:    0,
			expectError: false,
		},
		{
			name:        "zero value",
			params:      map[string]interface{}{"count": float64(0)},
			paramName:   "count",
			expected:    0,
			expectError: false,
		},
		{
			name:        "wrong type parameter",
			params:      map[string]interface{}{"count": "not-a-number"},
			paramName:   "count",
			expected:    0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := createMCPRequest(tc.params)
			result, err := OptionalIntParam(request, tc.paramName)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func Test_OptionalNumberParamWithDefault(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		paramName   string
		defaultVal  int
		expected    int
		expectError bool
	}{
		{
			name:        "valid number parameter",
			params:      map[string]interface{}{"count": float64(42)},
			paramName:   "count",
			defaultVal:  10,
			expected:    42,
			expectError: false,
		},
		{
			name:        "missing parameter",
			params:      map[string]interface{}{},
			paramName:   "count",
			defaultVal:  10,
			expected:    10,
			expectError: false,
		},
		{
			name:        "zero value",
			params:      map[string]interface{}{"count": float64(0)},
			paramName:   "count",
			defaultVal:  10,
			expected:    10,
			expectError: false,
		},
		{
			name:        "wrong type parameter",
			params:      map[string]interface{}{"count": "not-a-number"},
			paramName:   "count",
			defaultVal:  10,
			expected:    0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := createMCPRequest(tc.params)
			result, err := OptionalIntParamWithDefault(request, tc.paramName, tc.defaultVal)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func Test_OptionalBooleanParam(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		paramName   string
		expected    bool
		expectError bool
	}{
		{
			name:        "true value",
			params:      map[string]interface{}{"flag": true},
			paramName:   "flag",
			expected:    true,
			expectError: false,
		},
		{
			name:        "false value",
			params:      map[string]interface{}{"flag": false},
			paramName:   "flag",
			expected:    false,
			expectError: false,
		},
		{
			name:        "missing parameter",
			params:      map[string]interface{}{},
			paramName:   "flag",
			expected:    false,
			expectError: false,
		},
		{
			name:        "wrong type parameter",
			params:      map[string]interface{}{"flag": "not-a-boolean"},
			paramName:   "flag",
			expected:    false,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := createMCPRequest(tc.params)
			result, err := OptionalParam[bool](request, tc.paramName)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestOptionalStringArrayParam(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		paramName   string
		expected    []string
		expectError bool
	}{
		{
			name:        "parameter not in request",
			params:      map[string]any{},
			paramName:   "flag",
			expected:    []string{},
			expectError: false,
		},
		{
			name: "valid any array parameter",
			params: map[string]any{
				"flag": []any{"v1", "v2"},
			},
			paramName:   "flag",
			expected:    []string{"v1", "v2"},
			expectError: false,
		},
		{
			name: "valid string array parameter",
			params: map[string]any{
				"flag": []string{"v1", "v2"},
			},
			paramName:   "flag",
			expected:    []string{"v1", "v2"},
			expectError: false,
		},
		{
			name: "wrong type parameter",
			params: map[string]any{
				"flag": 1,
			},
			paramName:   "flag",
			expected:    []string{},
			expectError: true,
		},
		{
			name: "wrong slice type parameter",
			params: map[string]any{
				"flag": []any{"foo", 2},
			},
			paramName:   "flag",
			expected:    []string{},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := createMCPRequest(tc.params)
			result, err := OptionalStringArrayParam(request, tc.paramName)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestOptionalPaginationParams(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]any
		expected    PaginationParams
		expectError bool
	}{
		{
			name:   "no pagination parameters, default values",
			params: map[string]any{},
			expected: PaginationParams{
				page:    1,
				perPage: 30,
			},
			expectError: false,
		},
		{
			name: "page parameter, default perPage",
			params: map[string]any{
				"page": float64(2),
			},
			expected: PaginationParams{
				page:    2,
				perPage: 30,
			},
			expectError: false,
		},
		{
			name: "perPage parameter, default page",
			params: map[string]any{
				"perPage": float64(50),
			},
			expected: PaginationParams{
				page:    1,
				perPage: 50,
			},
			expectError: false,
		},
		{
			name: "page and perPage parameters",
			params: map[string]any{
				"page":    float64(2),
				"perPage": float64(50),
			},
			expected: PaginationParams{
				page:    2,
				perPage: 50,
			},
			expectError: false,
		},
		{
			name: "invalid page parameter",
			params: map[string]any{
				"page": "not-a-number",
			},
			expected:    PaginationParams{},
			expectError: true,
		},
		{
			name: "invalid perPage parameter",
			params: map[string]any{
				"perPage": "not-a-number",
			},
			expected:    PaginationParams{},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := createMCPRequest(tc.params)
			result, err := OptionalPaginationParams(request)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
```

---

## `pkg/github/tools.go`

```go
package github

import (
	"context"

	"github.com/github/github-mcp-server/pkg/toolsets"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/server"
)

type GetClientFn func(context.Context) (*github.Client, error)

var DefaultTools = []string{"all"}

func InitToolsets(passedToolsets []string, readOnly bool, getClient GetClientFn, t translations.TranslationHelperFunc) (*toolsets.ToolsetGroup, error) {
	// Create a new toolset group
	tsg := toolsets.NewToolsetGroup(readOnly)

	// Define all available features with their default state (disabled)
	// Create toolsets
	repos := toolsets.NewToolset("repos", "GitHub Repository related tools").
		AddReadTools(
			toolsets.NewServerTool(SearchRepositories(getClient, t)),
			toolsets.NewServerTool(GetFileContents(getClient, t)),
			toolsets.NewServerTool(ListCommits(getClient, t)),
			toolsets.NewServerTool(SearchCode(getClient, t)),
			toolsets.NewServerTool(GetCommit(getClient, t)),
			toolsets.NewServerTool(ListBranches(getClient, t)),
		).
		AddWriteTools(
			toolsets.NewServerTool(CreateOrUpdateFile(getClient, t)),
			toolsets.NewServerTool(CreateRepository(getClient, t)),
			toolsets.NewServerTool(ForkRepository(getClient, t)),
			toolsets.NewServerTool(CreateBranch(getClient, t)),
			toolsets.NewServerTool(PushFiles(getClient, t)),
		)
	issues := toolsets.NewToolset("issues", "GitHub Issues related tools").
		AddReadTools(
			toolsets.NewServerTool(GetIssue(getClient, t)),
			toolsets.NewServerTool(SearchIssues(getClient, t)),
			toolsets.NewServerTool(ListIssues(getClient, t)),
			toolsets.NewServerTool(GetIssueComments(getClient, t)),
		).
		AddWriteTools(
			toolsets.NewServerTool(CreateIssue(getClient, t)),
			toolsets.NewServerTool(AddIssueComment(getClient, t)),
			toolsets.NewServerTool(UpdateIssue(getClient, t)),
		)
	users := toolsets.NewToolset("users", "GitHub User related tools").
		AddReadTools(
			toolsets.NewServerTool(SearchUsers(getClient, t)),
		)
	pullRequests := toolsets.NewToolset("pull_requests", "GitHub Pull Request related tools").
		AddReadTools(
			toolsets.NewServerTool(GetPullRequest(getClient, t)),
			toolsets.NewServerTool(ListPullRequests(getClient, t)),
			toolsets.NewServerTool(GetPullRequestFiles(getClient, t)),
			toolsets.NewServerTool(GetPullRequestStatus(getClient, t)),
			toolsets.NewServerTool(GetPullRequestComments(getClient, t)),
			toolsets.NewServerTool(GetPullRequestReviews(getClient, t)),
		).
		AddWriteTools(
			toolsets.NewServerTool(MergePullRequest(getClient, t)),
			toolsets.NewServerTool(UpdatePullRequestBranch(getClient, t)),
			toolsets.NewServerTool(CreatePullRequestReview(getClient, t)),
			toolsets.NewServerTool(CreatePullRequest(getClient, t)),
			toolsets.NewServerTool(UpdatePullRequest(getClient, t)),
			toolsets.NewServerTool(AddPullRequestReviewComment(getClient, t)),
		)
	codeSecurity := toolsets.NewToolset("code_security", "Code security related tools, such as GitHub Code Scanning").
		AddReadTools(
			toolsets.NewServerTool(GetCodeScanningAlert(getClient, t)),
			toolsets.NewServerTool(ListCodeScanningAlerts(getClient, t)),
		)
	// Keep experiments alive so the system doesn't error out when it's always enabled
	experiments := toolsets.NewToolset("experiments", "Experimental features that are not considered stable yet")

	// Add toolsets to the group
	tsg.AddToolset(repos)
	tsg.AddToolset(issues)
	tsg.AddToolset(users)
	tsg.AddToolset(pullRequests)
	tsg.AddToolset(codeSecurity)
	tsg.AddToolset(experiments)
	// Enable the requested features

	if err := tsg.EnableToolsets(passedToolsets); err != nil {
		return nil, err
	}

	return tsg, nil
}

func InitContextToolset(getClient GetClientFn, t translations.TranslationHelperFunc) *toolsets.Toolset {
	// Create a new context toolset
	contextTools := toolsets.NewToolset("context", "Tools that provide context about the current user and GitHub context you are operating in").
		AddReadTools(
			toolsets.NewServerTool(GetMe(getClient, t)),
		)
	contextTools.Enabled = true
	return contextTools
}

// InitDynamicToolset creates a dynamic toolset that can be used to enable other toolsets, and so requires the server and toolset group as arguments
func InitDynamicToolset(s *server.MCPServer, tsg *toolsets.ToolsetGroup, t translations.TranslationHelperFunc) *toolsets.Toolset {
	// Create a new dynamic toolset
	// Need to add the dynamic toolset last so it can be used to enable other toolsets
	dynamicToolSelection := toolsets.NewToolset("dynamic", "Discover GitHub MCP tools that can help achieve tasks by enabling additional sets of tools, you can control the enablement of any toolset to access its tools when this toolset is enabled.").
		AddReadTools(
			toolsets.NewServerTool(ListAvailableToolsets(tsg, t)),
			toolsets.NewServerTool(GetToolsetsTools(tsg, t)),
			toolsets.NewServerTool(EnableToolset(s, tsg, t)),
		)
	dynamicToolSelection.Enabled = true
	return dynamicToolSelection
}
```

---

## `pkg/log/io.go`

```go
package log

import (
	"io"

	log "github.com/sirupsen/logrus"
)

// IOLogger is a wrapper around io.Reader and io.Writer that can be used
// to log the data being read and written from the underlying streams
type IOLogger struct {
	reader io.Reader
	writer io.Writer
	logger *log.Logger
}

// NewIOLogger creates a new IOLogger instance
func NewIOLogger(r io.Reader, w io.Writer, logger *log.Logger) *IOLogger {
	return &IOLogger{
		reader: r,
		writer: w,
		logger: logger,
	}
}

// Read reads data from the underlying io.Reader and logs it.
func (l *IOLogger) Read(p []byte) (n int, err error) {
	if l.reader == nil {
		return 0, io.EOF
	}
	n, err = l.reader.Read(p)
	if n > 0 {
		l.logger.Infof("[stdin]: received %d bytes: %s", n, string(p[:n]))
	}
	return n, err
}

// Write writes data to the underlying io.Writer and logs it.
func (l *IOLogger) Write(p []byte) (n int, err error) {
	if l.writer == nil {
		return 0, io.ErrClosedPipe
	}
	l.logger.Infof("[stdout]: sending %d bytes: %s", len(p), string(p))
	return l.writer.Write(p)
}
```

---

## `pkg/log/io_test.go`

```go
package log

import (
	"bytes"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLoggedReadWriter(t *testing.T) {
	t.Run("Read method logs and passes data", func(t *testing.T) {
		// Setup
		inputData := "test input data"
		reader := strings.NewReader(inputData)

		// Create logger with buffer to capture output
		var logBuffer bytes.Buffer
		logger := log.New()
		logger.SetOutput(&logBuffer)
		logger.SetFormatter(&log.TextFormatter{
			DisableTimestamp: true,
		})

		lrw := NewIOLogger(reader, nil, logger)

		// Test Read
		buf := make([]byte, 100)
		n, err := lrw.Read(buf)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, len(inputData), n)
		assert.Equal(t, inputData, string(buf[:n]))
		assert.Contains(t, logBuffer.String(), "[stdin]")
		assert.Contains(t, logBuffer.String(), inputData)
	})

	t.Run("Write method logs and passes data", func(t *testing.T) {
		// Setup
		outputData := "test output data"
		var writeBuffer bytes.Buffer

		// Create logger with buffer to capture output
		var logBuffer bytes.Buffer
		logger := log.New()
		logger.SetOutput(&logBuffer)
		logger.SetFormatter(&log.TextFormatter{
			DisableTimestamp: true,
		})

		lrw := NewIOLogger(nil, &writeBuffer, logger)

		// Test Write
		n, err := lrw.Write([]byte(outputData))

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, len(outputData), n)
		assert.Equal(t, outputData, writeBuffer.String())
		assert.Contains(t, logBuffer.String(), "[stdout]")
		assert.Contains(t, logBuffer.String(), outputData)
	})
}
```

---

## `pkg/toolsets/toolsets.go`

```go
package toolsets

import (
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func NewServerTool(tool mcp.Tool, handler server.ToolHandlerFunc) server.ServerTool {
	return server.ServerTool{Tool: tool, Handler: handler}
}

type Toolset struct {
	Name        string
	Description string
	Enabled     bool
	readOnly    bool
	writeTools  []server.ServerTool
	readTools   []server.ServerTool
}

func (t *Toolset) GetActiveTools() []server.ServerTool {
	if t.Enabled {
		if t.readOnly {
			return t.readTools
		}
		return append(t.readTools, t.writeTools...)
	}
	return nil
}

func (t *Toolset) GetAvailableTools() []server.ServerTool {
	if t.readOnly {
		return t.readTools
	}
	return append(t.readTools, t.writeTools...)
}

func (t *Toolset) RegisterTools(s *server.MCPServer) {
	if !t.Enabled {
		return
	}
	for _, tool := range t.readTools {
		s.AddTool(tool.Tool, tool.Handler)
	}
	if !t.readOnly {
		for _, tool := range t.writeTools {
			s.AddTool(tool.Tool, tool.Handler)
		}
	}
}

func (t *Toolset) SetReadOnly() {
	// Set the toolset to read-only
	t.readOnly = true
}

func (t *Toolset) AddWriteTools(tools ...server.ServerTool) *Toolset {
	// Silently ignore if the toolset is read-only to avoid any breach of that contract
	if !t.readOnly {
		t.writeTools = append(t.writeTools, tools...)
	}
	return t
}

func (t *Toolset) AddReadTools(tools ...server.ServerTool) *Toolset {
	t.readTools = append(t.readTools, tools...)
	return t
}

type ToolsetGroup struct {
	Toolsets     map[string]*Toolset
	everythingOn bool
	readOnly     bool
}

func NewToolsetGroup(readOnly bool) *ToolsetGroup {
	return &ToolsetGroup{
		Toolsets:     make(map[string]*Toolset),
		everythingOn: false,
		readOnly:     readOnly,
	}
}

func (tg *ToolsetGroup) AddToolset(ts *Toolset) {
	if tg.readOnly {
		ts.SetReadOnly()
	}
	tg.Toolsets[ts.Name] = ts
}

func NewToolset(name string, description string) *Toolset {
	return &Toolset{
		Name:        name,
		Description: description,
		Enabled:     false,
		readOnly:    false,
	}
}

func (tg *ToolsetGroup) IsEnabled(name string) bool {
	// If everythingOn is true, all features are enabled
	if tg.everythingOn {
		return true
	}

	feature, exists := tg.Toolsets[name]
	if !exists {
		return false
	}
	return feature.Enabled
}

func (tg *ToolsetGroup) EnableToolsets(names []string) error {
	// Special case for "all"
	for _, name := range names {
		if name == "all" {
			tg.everythingOn = true
			break
		}
		err := tg.EnableToolset(name)
		if err != nil {
			return err
		}
	}
	// Do this after to ensure all toolsets are enabled if "all" is present anywhere in list
	if tg.everythingOn {
		for name := range tg.Toolsets {
			err := tg.EnableToolset(name)
			if err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

func (tg *ToolsetGroup) EnableToolset(name string) error {
	toolset, exists := tg.Toolsets[name]
	if !exists {
		return fmt.Errorf("toolset %s does not exist", name)
	}
	toolset.Enabled = true
	tg.Toolsets[name] = toolset
	return nil
}

func (tg *ToolsetGroup) RegisterTools(s *server.MCPServer) {
	for _, toolset := range tg.Toolsets {
		toolset.RegisterTools(s)
	}
}
```

---

## `pkg/toolsets/toolsets_test.go`

```go
package toolsets

import (
	"testing"
)

func TestNewToolsetGroup(t *testing.T) {
	tsg := NewToolsetGroup(false)
	if tsg == nil {
		t.Fatal("Expected NewToolsetGroup to return a non-nil pointer")
	}
	if tsg.Toolsets == nil {
		t.Fatal("Expected Toolsets map to be initialized")
	}
	if len(tsg.Toolsets) != 0 {
		t.Fatalf("Expected Toolsets map to be empty, got %d items", len(tsg.Toolsets))
	}
	if tsg.everythingOn {
		t.Fatal("Expected everythingOn to be initialized as false")
	}
}

func TestAddToolset(t *testing.T) {
	tsg := NewToolsetGroup(false)

	// Test adding a toolset
	toolset := NewToolset("test-toolset", "A test toolset")
	toolset.Enabled = true
	tsg.AddToolset(toolset)

	// Verify toolset was added correctly
	if len(tsg.Toolsets) != 1 {
		t.Errorf("Expected 1 toolset, got %d", len(tsg.Toolsets))
	}

	toolset, exists := tsg.Toolsets["test-toolset"]
	if !exists {
		t.Fatal("Feature was not added to the map")
	}

	if toolset.Name != "test-toolset" {
		t.Errorf("Expected toolset name to be 'test-toolset', got '%s'", toolset.Name)
	}

	if toolset.Description != "A test toolset" {
		t.Errorf("Expected toolset description to be 'A test toolset', got '%s'", toolset.Description)
	}

	if !toolset.Enabled {
		t.Error("Expected toolset to be enabled")
	}

	// Test adding another toolset
	anotherToolset := NewToolset("another-toolset", "Another test toolset")
	tsg.AddToolset(anotherToolset)

	if len(tsg.Toolsets) != 2 {
		t.Errorf("Expected 2 toolsets, got %d", len(tsg.Toolsets))
	}

	// Test overriding existing toolset
	updatedToolset := NewToolset("test-toolset", "Updated description")
	tsg.AddToolset(updatedToolset)

	toolset = tsg.Toolsets["test-toolset"]
	if toolset.Description != "Updated description" {
		t.Errorf("Expected toolset description to be updated to 'Updated description', got '%s'", toolset.Description)
	}

	if toolset.Enabled {
		t.Error("Expected toolset to be disabled after update")
	}
}

func TestIsEnabled(t *testing.T) {
	tsg := NewToolsetGroup(false)

	// Test with non-existent toolset
	if tsg.IsEnabled("non-existent") {
		t.Error("Expected IsEnabled to return false for non-existent toolset")
	}

	// Test with disabled toolset
	disabledToolset := NewToolset("disabled-toolset", "A disabled toolset")
	tsg.AddToolset(disabledToolset)
	if tsg.IsEnabled("disabled-toolset") {
		t.Error("Expected IsEnabled to return false for disabled toolset")
	}

	// Test with enabled toolset
	enabledToolset := NewToolset("enabled-toolset", "An enabled toolset")
	enabledToolset.Enabled = true
	tsg.AddToolset(enabledToolset)
	if !tsg.IsEnabled("enabled-toolset") {
		t.Error("Expected IsEnabled to return true for enabled toolset")
	}
}

func TestEnableFeature(t *testing.T) {
	tsg := NewToolsetGroup(false)

	// Test enabling non-existent toolset
	err := tsg.EnableToolset("non-existent")
	if err == nil {
		t.Error("Expected error when enabling non-existent toolset")
	}

	// Test enabling toolset
	testToolset := NewToolset("test-toolset", "A test toolset")
	tsg.AddToolset(testToolset)

	if tsg.IsEnabled("test-toolset") {
		t.Error("Expected toolset to be disabled initially")
	}

	err = tsg.EnableToolset("test-toolset")
	if err != nil {
		t.Errorf("Expected no error when enabling toolset, got: %v", err)
	}

	if !tsg.IsEnabled("test-toolset") {
		t.Error("Expected toolset to be enabled after EnableFeature call")
	}

	// Test enabling already enabled toolset
	err = tsg.EnableToolset("test-toolset")
	if err != nil {
		t.Errorf("Expected no error when enabling already enabled toolset, got: %v", err)
	}
}

func TestEnableToolsets(t *testing.T) {
	tsg := NewToolsetGroup(false)

	// Prepare toolsets
	toolset1 := NewToolset("toolset1", "Feature 1")
	toolset2 := NewToolset("toolset2", "Feature 2")
	tsg.AddToolset(toolset1)
	tsg.AddToolset(toolset2)

	// Test enabling multiple toolsets
	err := tsg.EnableToolsets([]string{"toolset1", "toolset2"})
	if err != nil {
		t.Errorf("Expected no error when enabling toolsets, got: %v", err)
	}

	if !tsg.IsEnabled("toolset1") {
		t.Error("Expected toolset1 to be enabled")
	}

	if !tsg.IsEnabled("toolset2") {
		t.Error("Expected toolset2 to be enabled")
	}

	// Test with non-existent toolset in the list
	err = tsg.EnableToolsets([]string{"toolset1", "non-existent"})
	if err == nil {
		t.Error("Expected error when enabling list with non-existent toolset")
	}

	// Test with empty list
	err = tsg.EnableToolsets([]string{})
	if err != nil {
		t.Errorf("Expected no error with empty toolset list, got: %v", err)
	}

	// Test enabling everything through EnableToolsets
	tsg = NewToolsetGroup(false)
	err = tsg.EnableToolsets([]string{"all"})
	if err != nil {
		t.Errorf("Expected no error when enabling 'all', got: %v", err)
	}

	if !tsg.everythingOn {
		t.Error("Expected everythingOn to be true after enabling 'all' via EnableToolsets")
	}
}

func TestEnableEverything(t *testing.T) {
	tsg := NewToolsetGroup(false)

	// Add a disabled toolset
	testToolset := NewToolset("test-toolset", "A test toolset")
	tsg.AddToolset(testToolset)

	// Verify it's disabled
	if tsg.IsEnabled("test-toolset") {
		t.Error("Expected toolset to be disabled initially")
	}

	// Enable "all"
	err := tsg.EnableToolsets([]string{"all"})
	if err != nil {
		t.Errorf("Expected no error when enabling 'eall', got: %v", err)
	}

	// Verify everythingOn was set
	if !tsg.everythingOn {
		t.Error("Expected everythingOn to be true after enabling 'eall'")
	}

	// Verify the previously disabled toolset is now enabled
	if !tsg.IsEnabled("test-toolset") {
		t.Error("Expected toolset to be enabled when everythingOn is true")
	}

	// Verify a non-existent toolset is also enabled
	if !tsg.IsEnabled("non-existent") {
		t.Error("Expected non-existent toolset to be enabled when everythingOn is true")
	}
}

func TestIsEnabledWithEverythingOn(t *testing.T) {
	tsg := NewToolsetGroup(false)

	// Enable "everything"
	err := tsg.EnableToolsets([]string{"all"})
	if err != nil {
		t.Errorf("Expected no error when enabling 'all', got: %v", err)
	}

	// Test that any toolset name returns true with IsEnabled
	if !tsg.IsEnabled("some-toolset") {
		t.Error("Expected IsEnabled to return true for any toolset when everythingOn is true")
	}

	if !tsg.IsEnabled("another-toolset") {
		t.Error("Expected IsEnabled to return true for any toolset when everythingOn is true")
	}
}
```

---

## `pkg/translations/translations.go`

```go
package translations

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/viper"
)

type TranslationHelperFunc func(key string, defaultValue string) string

func NullTranslationHelper(_ string, defaultValue string) string {
	return defaultValue
}

func TranslationHelper() (TranslationHelperFunc, func()) {
	var translationKeyMap = map[string]string{}
	v := viper.New()

	// Load from JSON file
	v.SetConfigName("github-mcp-server-config")
	v.SetConfigType("json")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		// ignore error if file not found as it is not required
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Printf("Could not read JSON config: %v", err)
		}
	}

	// create a function that takes both a key, and a default value and returns either the default value or an override value
	return func(key string, defaultValue string) string {
			key = strings.ToUpper(key)
			if value, exists := translationKeyMap[key]; exists {
				return value
			}
			// check if the env var exists
			if value, exists := os.LookupEnv("GITHUB_MCP_" + key); exists {
				// TODO I could not get Viper to play ball reading the env var
				translationKeyMap[key] = value
				return value
			}

			v.SetDefault(key, defaultValue)
			translationKeyMap[key] = v.GetString(key)
			return translationKeyMap[key]
		}, func() {
			// dump the translationKeyMap to a json file
			if err := DumpTranslationKeyMap(translationKeyMap); err != nil {
				log.Fatalf("Could not dump translation key map: %v", err)
			}
		}
}

// dump translationKeyMap to a json file called github-mcp-server-config.json
func DumpTranslationKeyMap(translationKeyMap map[string]string) error {
	file, err := os.Create("github-mcp-server-config.json")
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer func() { _ = file.Close() }()

	// marshal the map to json
	jsonData, err := json.MarshalIndent(translationKeyMap, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling map to JSON: %v", err)
	}

	// write the json data to the file
	if _, err := file.Write(jsonData); err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	return nil
}
```

---

## `script/get-me`

```
#!/bin/bash

echo '{"jsonrpc":"2.0","id":3,"params":{"name":"get_me"},"method":"tools/call"}' | go run  cmd/github-mcp-server/main.go stdio  | jq .
```

---

## `script/licenses`

```
#!/bin/bash

go install github.com/google/go-licenses@latest

rm -rf third-party
mkdir -p third-party
export TEMPDIR="$(mktemp -d)"

trap "rm -fr ${TEMPDIR}" EXIT

for goos in linux darwin windows ; do
    # Note: we ignore warnings because we want the command to succeed, however the output should be checked
    #       for any new warnings, and potentially we may need to add license information. 
    #
    #       Normally these warnings are packages containing non go code, which may or may not require explicit attribution,
    #       depending on the license.
    GOOS="${goos}" go-licenses save ./... --save_path="${TEMPDIR}/${goos}" --force || echo "Ignore warnings"
    GOOS="${goos}" go-licenses report ./... --template .github/licenses.tmpl > third-party-licenses.${goos}.md || echo "Ignore warnings"
    cp -fR "${TEMPDIR}/${goos}"/* third-party/
done

```

---

## `script/licenses-check`

```
#!/bin/bash

go install github.com/google/go-licenses@latest

for goos in linux darwin windows ; do
    # Note: we ignore warnings because we want the command to succeed, however the output should be checked
    #       for any new warnings, and potentially we may need to add license information. 
    #
    #       Normally these warnings are packages containing non go code, which may or may not require explicit attribution,
    #       depending on the license.
    GOOS="${goos}" go-licenses report ./... --template .github/licenses.tmpl > third-party-licenses.${goos}.copy.md || echo "Ignore warnings"
    if ! diff -s third-party-licenses.${goos}.copy.md third-party-licenses.${goos}.md; then
        echo "License check failed.\n\nPlease update the license file by running \`.script/licenses\` and committing the output."
        rm -f third-party-licenses.${goos}.copy.md
        exit 1
    fi
    rm -f third-party-licenses.${goos}.copy.md
done



```

---

## `script/prettyprint-log`

```
#!/bin/bash

# Script to pretty print the output of the github-mcp-server
# log.
#
# It uses colored output when running on a terminal.

# show script help
show_help() {
  cat <<EOF
Usage: $(basename "$0") [file]

If [file] is provided, input is read from that file.
If no argument is given, input is read from stdin.

Options:
  -h, --help      Show this help message and exit
EOF
}

# choose color for stdin or stdout if we are printing to
# an actual terminal
color(){
  io="$1"
  if [[ "$io" == "stdin" ]]; then
    color="\033[0;32m" # green
  else
    color="\033[0;36m" # cyan
  fi
  if [ ! $is_terminal = "1" ]; then
    color=""
  fi
  echo -e "${color}[$io]"
}

# reset code if we are printing to an actual terminal
reset(){
  if [ ! $is_terminal = "1" ]; then
    return
  fi
  echo -e "\033[0m"
}


# Handle -h or --help
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  show_help
  exit 0
fi

# Determine input source
if [[ -n "$1" ]]; then
  if [[ ! -r "$1" ]]; then
    echo "Error: File '$1' not found or not readable." >&2
    exit 1
  fi
  input="$1"
else
  input="/dev/stdin"
fi

# check if we are in a terminal for showing colors
if test -t 1; then
  is_terminal="1"
else
  is_terminal="0"
fi

# Processs each log line, print whether is stdin or stdout, using different
# colors if we output to a terminal, and pretty print json data using jq
sed -nE 's/^.*\[(stdin|stdout)\]:.* ([0-9]+) bytes: (.*)\\n"$/\1 \2 \3/p' $input |
while read -r io bytes json; do
  # Unescape the JSON string safely
  unescaped=$(echo "$json" | awk '{ print "echo -e \"" $0 "\" | jq ." }' | bash)
  echo  "$(color $io)($bytes bytes):$(reset)"
  echo "$unescaped" | jq .
  echo
done
```

---

## `third-party/github.com/fsnotify/fsnotify/LICENSE`

```
Copyright © 2012 The Go Authors. All rights reserved.
Copyright © fsnotify Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.
* Neither the name of Google Inc. nor the names of its contributors may be used
  to endorse or promote products derived from this software without specific
  prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## `third-party/github.com/github/github-mcp-server/LICENSE`

```
MIT License

Copyright (c) 2025 GitHub

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## `third-party/github.com/go-viper/mapstructure/v2/LICENSE`

```
The MIT License (MIT)

Copyright (c) 2013 Mitchell Hashimoto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

## `third-party/github.com/google/go-github/v69/github/LICENSE`

```
Copyright (c) 2013 The go-github AUTHORS. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## `third-party/github.com/google/go-querystring/query/LICENSE`

```
Copyright (c) 2013 Google. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## `third-party/github.com/google/uuid/LICENSE`

```
Copyright (c) 2009,2014 Google Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## `third-party/github.com/inconshreveable/mousetrap/LICENSE`

```
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright 2022 Alan Shreve (@inconshreveable)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

---

## `third-party/github.com/mark3labs/mcp-go/LICENSE`

```
MIT License

Copyright (c) 2024 Anthropic, PBC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## `third-party/github.com/pelletier/go-toml/v2/LICENSE`

```
The MIT License (MIT)

go-toml v2
Copyright (c) 2021 - 2023 Thomas Pelletier

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## `third-party/github.com/sagikazarmark/locafero/LICENSE`

```
Copyright (c) 2023 Márk Sági-Kazár <mark.sagikazar@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

## `third-party/github.com/sirupsen/logrus/LICENSE`

```
The MIT License (MIT)

Copyright (c) 2014 Simon Eskildsen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

## `third-party/github.com/sourcegraph/conc/LICENSE`

```
MIT License

Copyright (c) 2023 Sourcegraph

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## `third-party/github.com/spf13/afero/LICENSE.txt`

```
                                Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.
```

---

## `third-party/github.com/spf13/cast/LICENSE`

```
The MIT License (MIT)

Copyright (c) 2014 Steve Francia

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.```

---

## `third-party/github.com/spf13/cobra/LICENSE.txt`

```
                                Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.
```

---

## `third-party/github.com/spf13/pflag/LICENSE`

```
Copyright (c) 2012 Alex Ogier. All rights reserved.
Copyright (c) 2012 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## `third-party/github.com/spf13/viper/LICENSE`

```
The MIT License (MIT)

Copyright (c) 2014 Steve Francia

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.```

---

## `third-party/github.com/subosito/gotenv/LICENSE`

```
The MIT License (MIT)

Copyright (c) 2013 Alif Rachmawadi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

## `third-party/github.com/yosida95/uritemplate/v3/LICENSE`

```
Copyright (C) 2016, Kohei YOSHIDA <https://yosida95.com/>. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright holder nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## `third-party/golang.org/x/sys/unix/LICENSE`

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## `third-party/golang.org/x/sys/windows/LICENSE`

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## `third-party/golang.org/x/text/LICENSE`

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## `third-party/gopkg.in/yaml.v3/LICENSE`

```

This project is covered by two different licenses: MIT and Apache.

#### MIT License ####

The following files were ported to Go from C files of libyaml, and thus
are still covered by their original MIT license, with the additional
copyright staring in 2011 when the project was ported over:

    apic.go emitterc.go parserc.go readerc.go scannerc.go
    writerc.go yamlh.go yamlprivateh.go

Copyright (c) 2006-2010 Kirill Simonov
Copyright (c) 2006-2011 Kirill Simonov

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

### Apache License ###

All the remaining project files are covered by the Apache license:

Copyright (c) 2011-2019 Canonical Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## `third-party/gopkg.in/yaml.v3/NOTICE`

```
Copyright 2011-2016 Canonical Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

