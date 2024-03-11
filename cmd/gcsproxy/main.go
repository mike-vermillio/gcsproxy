package main

import (
	"context"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"go.opentelemetry.io/otel/sdk/resource"
)

var (
	bind          = flag.String("b", "127.0.0.1:8080", "Bind address.")
	creds         = flag.String("c", "", "The path to the keyfile. If not present, client will use your default application credentials.")
	redirect404   = flag.Bool("r", false, "Redirect to index.html if 404 not found.")
	listDirectory = flag.Bool("list-directory", false, "Show directory listing if requested path is not found")
	indexPage     = flag.String("i", "", "Index page file name.")
	useDomainName = flag.Bool("dn", false, "Use hostname as a bucket name.")
	forceBucket   = flag.String("force-bucket", "", "Force bucket name.")
	prefix        = flag.String("prefix", "", "Use a prefix for all paths specified.")
	useSecret     = flag.String("s", "", "Use SA key from secretManager. E.G. 'projects/937192795301/secrets/gcs-proxy/versions/1'")
	verbose       = flag.Bool("v", false, "Show access log.")

	enableOtel = flag.Bool("otel", false, "Enable opentelemetry.")

	templateString = `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Directory Listing</title>
		<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
		<style>
			/* Additional styling for sorting indicators */
			.sort-header {
				cursor: pointer;
			}

			.sort-asc::after {
				content: " ▲";
				font-weight: bold;
			}

			.sort-desc::after {
				content: " ▼";
				font-weight: bold;
			}
		</style>

		<!-- Include jQuery (required for Tablesorter) -->
		<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
	
		<!-- Include the Tablesorter library -->
		<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.3/js/jquery.tablesorter.min.js"></script>
		
		<script>
			$(document).ready(function () {
				$(".tablesorter").tablesorter({
					cssIconAsc: 'sort-asc',
					cssIconDesc: 'sort-desc',
					headerTemplate: '{content}{icon}'
				});
			});
		</script>
	</head>
	<body class="bg-gray-100 p-8">
	
		<div class="max-w-full mx-auto">
			<h1 class="text-2xl font-bold mb-4">Directory Listing: {{.Prefix}}</h1>
	
			<div class="overflow-x-auto">
				<table class="tablesorter min-w-full border bg-white">
					<thead class="bg-gray-50">
						<tr>
							<th class="text-left py-2 px-4 border-b w-1/12 sort-header">Type</th>
							<th class="text-left py-2 px-4 border-b w-6/12 sort-header">Name</th>
							<th class="text-left py-2 px-4 border-b w-3/12 sort-header">Last Modified</th>
							<th class="text-left py-2 px-4 border-b w-2/12 sort-header">Size</th>
						</tr>
					</thead>
					<tbody>
						{{if ne .Prefix ""}}
						<tr>
							<td class="py-2 px-4 border-b w-1/12">
								<i class="fas fa-folder text-green-500"></i>
								<span class="invisible">Dir</span>
							</td>
							<td class="py-2 px-4 border-b w-6/12">
								<a href=".." class="text-blue-500 font-semibold">..</a>
							</td>
							<td class="py-2 px-4 border-b w-3/12">--</td>
							<td class="py-2 px-4 border-b w-2/12">--</td>
						</tr>
						{{end}}
						{{range .Items}}
							<tr>
								<td class="py-2 px-4 border-b w-1/12">
									{{if .IsDir}}
										<i class="fas fa-folder text-green-500"></i>
										<span class="invisible">Dir</span>
									{{else}}
										<i class="fas fa-file text-gray-500"></i>
										<span class="invisible">File</span>
									{{end}}
								</td>
								<td class="py-2 px-4 border-b w-6/12">
									<a href="{{.Link}}" class="text-blue-500 font-semibold">{{.Name}}</a>
								</td>
								<td class="py-2 px-4 border-b w-3/12">
									{{if .IsDir}}--{{else}}{{.ModTime.Format "2006-01-02 15:04:05"}}{{end}}
								</td>
								<td class="py-2 px-4 border-b w-2/12">
									{{if .IsDir}}--{{else}}{{formatSize .Size}}{{end}}
								</td>
								</td>
							</tr>
						{{end}}
					</tbody>
				</table>
			</div>
		</div>
	
	</body>
	</html>`
)

func formatSize(size int64) string {
	const (
		B = 1 << (10 * iota)
		KB
		MB
		GB
		TB
		PB
		EB
	)

	value := float64(size)
	unit := ""

	switch {
	case size < KB:
		unit = "B"
	case size < MB:
		value /= KB
		unit = "KB"
	case size < GB:
		value /= MB
		unit = "MB"
	case size < TB:
		value /= GB
		unit = "GB"
	case size < PB:
		value /= TB
		unit = "TB"
	case size < EB:
		value /= PB
		unit = "PB"
	default:
		value /= EB
		unit = "EB"
	}

	return strconv.FormatFloat(value, 'f', 2, 64) + " " + unit
}

type ItemType string

type TemplateItem struct {
	IsDir   bool
	Name    string
	Link    template.URL
	Size    int64
	ModTime time.Time
	Attrs   *storage.ObjectAttrs
}
type TemplateData struct {
	Prefix string
	Items  []TemplateItem
}

var (
	client *storage.Client
	ctx    = context.Background()
)

func handleErrorRW(w http.ResponseWriter, err error) {
	if err != nil {
		if err == storage.ErrObjectNotExist {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
}

func handleErrStr(err error, message string) {
	if err != nil {
		log.Fatalf("%s: %v", message, err)
	}
}

func header(r *http.Request, key string) (string, bool) {
	if r.Header == nil {
		return "", false
	}
	if candidate := r.Header[key]; len(candidate) > 0 {
		return candidate[0], true
	}
	return "", false
}

func setStrHeader(w http.ResponseWriter, key string, value string) {
	if value != "" {
		w.Header().Add(key, value)
	}
}

func setIntHeader(w http.ResponseWriter, key string, value int64) {
	if value > 0 {
		w.Header().Add(key, strconv.FormatInt(value, 10))
	}
}

type wrapResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *wrapResponseWriter) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	w.status = status
}

func wrapper(fn func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proc := time.Now()
		writer := &wrapResponseWriter{
			ResponseWriter: w,
			status:         http.StatusOK,
		}
		fn(writer, r)
		addr := r.RemoteAddr
		if ip, found := header(r, "X-Forwarded-For"); found {
			addr = ip
		}
		if *verbose {
			log.Printf("[%s] %.3f %d %s %s",
				addr,
				time.Since(proc).Seconds(),
				writer.status,
				r.Method,
				r.URL,
			)
		}
	}
}

func proxy(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)

	// Redefine bucket name, in case our bucket name in the following format 'site.example.com'.
	if *useDomainName {
		params["bucket"] = r.Host
	}

	// If we are forcing the bucket name, read from it, don't expect it in the URL
	if *forceBucket != "" {
		params["bucket"] = *forceBucket
	}

	path := ""
	if *prefix != "" {
		path = *prefix
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
	}

	// Set index page name
	if *indexPage != "" && params["object"] == "" {
		path += *indexPage
	} else {
		path += params["object"]
	}

	bucket := client.Bucket(params["bucket"])

	if path == "" && *listDirectory {
		path = "/" // hacky but works for now...
	}

	fmt.Printf("Checking path %s\n", path)
	obj := bucket.Object(path).ReadCompressed(acceptsGzip(r))
	attr, err := obj.Attrs(ctx)

	if err == storage.ErrObjectNotExist || (attr.Size == 0 && strings.HasSuffix(path, "/")) {
		if *redirect404 {
			// Remove first slash, otherwise it won't find an object. Add tailing slash if missing.
			if !strings.HasSuffix(path, "/") {
				path += "/"
			}

			obj = bucket.Object(path + *indexPage)
			attr, err = obj.Attrs(ctx)

			if err == storage.ErrObjectNotExist && path == "/" {
				obj = bucket.Object(*indexPage)
				attr, err = obj.Attrs(ctx)
			}
		} else if *listDirectory {
			if strings.HasPrefix(path, "/") {
				path = path[1:]
			}

			if path != "" && !strings.HasSuffix(path, "/") {
				path += "/"
			}

			fmt.Printf("Listing directory %s\n", path)
			it := bucket.Objects(ctx, &storage.Query{
				Prefix:    path,
				Delimiter: "/",
			})

			var items []TemplateItem
			for {
				attrs, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					fmt.Errorf("Bucket(%q).Objects(): %w", bucket, err)
					break
				}

				name := attrs.Name
				isDir := false
				if attrs.Prefix != "" {
					name = attrs.Prefix
					isDir = true
				}

				name = strings.Replace(name, path, "", 1)
				if !isDir && attrs.Size == 0 && name == "" { // empty hidden files for directories?
					continue
				}

				link := name
				if !strings.HasSuffix(params["object"], "/") {
					link = params["object"] + "/" + link
				}

				items = append(items, TemplateItem{
					IsDir:   isDir,
					Name:    name,
					Link:    template.URL(link),
					Size:    attrs.Size,
					ModTime: attrs.Updated,
					Attrs:   attrs,
				})
			}

			tpl, err := template.New("directory").Funcs(template.FuncMap{"formatSize": formatSize}).Parse(templateString)
			if err != nil {
				panic(err)
			}

			fmt.Printf("Found %d items @%s\n", len(items), path)
			sort.Slice(items, func(i, j int) bool {
				return strings.Compare(items[i].Name, items[j].Name) < 0
			})

			pfx := path
			if *prefix != "" {
				pfx = strings.Replace(pfx, *prefix, "", 1)
			}

			if strings.HasPrefix(pfx, "/") {
				pfx = pfx[1:]
			}

			tpl.Execute(w, TemplateData{
				Prefix: pfx,
				Items:  items,
			})

			setStrHeader(w, "Content-Type", "text/html; charset=utf-8")
			setStrHeader(w, "Cache-Control", "max-age=3600, public")
			setStrHeader(w, "X-Goog-Authenticated-User-Id", r.Header.Get("X-Goog-Authenticated-User-Id"))
			setStrHeader(w, "X-Goog-Authenticated-User-Email", r.Header.Get("X-Goog-Authenticated-User-Email"))

			return
		}
	}

	if err != nil {
		handleErrorRW(w, err)
		return
	}

	setStrHeader(w, "Content-Type", attr.ContentType)
	setStrHeader(w, "Content-Language", attr.ContentLanguage)
	setStrHeader(w, "Cache-Control", attr.CacheControl)
	setStrHeader(w, "Content-Encoding", attr.ContentEncoding)
	setStrHeader(w, "Content-Disposition", attr.ContentDisposition)
	setStrHeader(w, "X-Goog-Authenticated-User-Id", r.Header.Get("X-Goog-Authenticated-User-Id"))
	setStrHeader(w, "X-Goog-Authenticated-User-Email", r.Header.Get("X-Goog-Authenticated-User-Email"))

	objr, err := obj.NewReader(ctx)
	if err != nil {
		handleErrorRW(w, err)
		return
	}
	var bytesWritten int64
	bytesWritten, err = io.Copy(w, objr)
	if err != nil {
		handleErrorRW(w, err)
		return
	}
	setIntHeader(w, "Content-Length", bytesWritten)
}

func acceptsGzip(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
}

func initTracer() *sdktrace.TracerProvider {
	ctx := context.Background()
	var connType otlptracegrpc.Option

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "127.0.0.1:4317" // setting default endpoint for exporter
	}

	insecure := os.Getenv("OTEL_EXPORTER_OTLP_SECURE")
	if insecure == "" || insecure == "false" {
		connType = otlptracegrpc.WithInsecure()
	} else {
		connType = otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, ""))
	}

	// Create and start new OTLP trace exporter
	traceExporter, err := otlptracegrpc.New(ctx, connType, otlptracegrpc.WithEndpoint(endpoint), otlptracegrpc.WithDialOption(grpc.WithBlock()))
	handleErrStr(err, "failed to create new OTLP trace exporter")

	service := os.Getenv("GO_GORILLA_SERVICE_NAME")
	if service == "" {
		service = "gcs-proxy"
	}

	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		// the service name used to display traces in backends
		semconv.ServiceNameKey.String(service),
	)
	handleErrStr(err, "failed to create resource")

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(traceExporter),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	return tp
}

func main() {
	flag.Parse()

	var err error
	var path string

	if *creds != "" {
		client, err = storage.NewClient(ctx, option.WithCredentialsFile(*creds))
		// } else if *useSecret != "" {
		// 	client, err = storage.NewClient(ctx, option.WithCredentialsFile(GetSecret(*useSecret)))
	} else {
		client, err = storage.NewClient(ctx)
	}

	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	if !*useDomainName && *forceBucket == "" {
		path = "/{bucket:[0-9a-zA-Z-_.]+}"
	}

	r := mux.NewRouter()

	if *enableOtel {
		tp := initTracer()
		defer func() {
			if err := tp.Shutdown(context.Background()); err != nil {
				log.Printf("Error shutting down tracer provider: %v", err)
			}
		}()
		r.Use(otelmux.Middleware("gcs-proxy"))
	}

	r.HandleFunc(path+"/{object:.*}", wrapper(proxy)).Methods("GET", "HEAD", "POST")

	log.Printf("[service] listening on %s", *bind)
	if err := http.ListenAndServe(*bind, r); err != nil {
		log.Fatal(err)
	}
}
