package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/projectdiscovery/gologger"
)

// GologgerLogger adapts structured scanner logs for the CLI.
type GologgerLogger struct {
	DebugRequest  bool
	DebugResponse bool
}

func (l GologgerLogger) Debug(_ context.Context, message string, fields ...any) {
	if message == "probe sent" && l.DebugRequest {
		if request, ok := fieldBytes(fields, "request"); ok {
			gologger.Print().Msgf("Dump Request for %s probe %s\n%s", fieldString(fields, "target"), fieldString(fields, "probe"), formatProbeData(request))
		}
	}
	if message == "probe response" && l.DebugResponse {
		if response, ok := fieldBytes(fields, "response"); ok {
			gologger.Print().Msgf("Read Response for %s probe %s\n%s", fieldString(fields, "target"), fieldString(fields, "probe"), formatProbeData(response))
		}
	}
	gologger.Debug().Msgf("%s%s", message, formatLogFields(fields))
}

func (GologgerLogger) Info(_ context.Context, message string, fields ...any) {
	gologger.Info().Msgf("%s%s", message, formatLogFields(fields))
}

func (GologgerLogger) Warn(_ context.Context, message string, fields ...any) {
	gologger.Warning().Msgf("%s%s", message, formatLogFields(fields))
}

func (GologgerLogger) Error(_ context.Context, err error, message string, fields ...any) {
	gologger.Debug().Msgf("%s error=%v%s", message, err, formatLogFields(fields))
}

func fieldString(fields []any, name string) string {
	for index := 0; index+1 < len(fields); index += 2 {
		if fields[index] == name {
			return fmt.Sprint(fields[index+1])
		}
	}
	return ""
}

func formatLogFields(fields []any) string {
	parts := make([]string, 0, len(fields)/2)
	for index := 0; index+1 < len(fields); index += 2 {
		key := fmt.Sprint(fields[index])
		if key == "request" || key == "response" {
			continue
		}
		parts = append(parts, key+"="+fmt.Sprint(fields[index+1]))
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, " ")
}

func fieldBytes(fields []any, name string) ([]byte, bool) {
	for index := 0; index+1 < len(fields); index += 2 {
		if fields[index] == name {
			value, ok := fields[index+1].([]byte)
			return value, ok
		}
	}
	return nil, false
}
