package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/SlyMarbo/rss"
)

const (
	cacheFile            string = "cache.json"
	defaultRssFeedSource string = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml"

	defaultOutputFormatting string = `----
{{ .Title }}
{{ .Date }}
{{ .Summary }}
{{ .Link }}
----
`
)

var (
	feedUrl      string
	confPath     string
	cachePath    string
	formatOutput string
)

func getEnvOr(key, defaultVal string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		return defaultVal
	} else {
		return val
	}
}

func loadCachedFeed(feedPath string) (*rss.Feed, error) {
	cachedFeed := &rss.Feed{}

	cachedFileData, err := os.ReadFile(feedPath)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(cachedFileData, cachedFeed); err != nil {
		return nil, err
	}

	return cachedFeed, nil
}

func cacheFeed(cachePath string, feed *rss.Feed) error {
	// mark all items as read prior to caching
	for _, item := range feed.Items {
		item.Read = true
	}
	feed.Unread = 0

	data, err := json.Marshal(feed)
	if err != nil {
		return err
	}

	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		return err
	}

	return nil
}

func fetch_feed(feedUrl, absoluteCacheFilePath string) (*rss.Feed, bool, error) {
	req, err := url.Parse(feedUrl)
	if err != nil {
		log.Fatal(err)
	}

	feed, err := loadCachedFeed(absoluteCacheFilePath)
	cached := false

	// update the feed from cache
	if !errors.Is(err, os.ErrNotExist) {
		err := feed.Update()
		if err != nil {
			return nil, cached, err
		}

		cached = true
	} else {
		upstream, err := rss.Fetch(req.String())
		if err != nil {
			return nil, cached, err
		}

		feed = upstream
		cached = false
	}

	return feed, cached, err
}

func printHelp() {
	fmt.Println("Usage: sec-feed [OPTIONS]...")
	fmt.Printf("A cli checker utility for generating vulnerabilty feeds.\n\n")
	flag.PrintDefaults()
}

func cmdNewItems(feed *rss.Feed, cacheFilePath string, filters map[string]string, cached bool) error {
	var newItems []*rss.Item

	if cached {
		for _, item := range feed.Items {
			if !item.Read {
				newItems = append(newItems, item)
			}
		}
	}

	if err := cacheFeed(cacheFilePath, feed); err != nil {
		return fmt.Errorf("failed to cache %s: %s", cacheFilePath, err)
	}

	// setup template
	outputTemplate, err := template.New("output").Parse(formatOutput)
	if err != nil {
		return err
	}

	var newItemsMatchingFilters []*rss.Item
	for _, item := range newItems {
		for _, filter := range filters {
			if strings.Contains(item.Title, filter) {
				newItemsMatchingFilters = append(newItemsMatchingFilters, item)
				break
			}
		}
	}

	for _, item := range newItemsMatchingFilters {
		err = outputTemplate.Execute(os.Stdout, item)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	help := flag.Bool("help", false, "print help information")
	flag.StringVar(&feedUrl, "url", getEnvOr("SEC_FEED_URL", defaultRssFeedSource), "the url source feed")
	flag.StringVar(&confPath, "filter-path", getEnvOr("SEC_FEED_FILTER_PATH", "conf"), "the directory path to source filters from")
	flag.StringVar(&cachePath, "cache-path", getEnvOr("SEC_FEED_CACHE_PATH", ".sec-feed/"), "the directory path to store all cache files")
	flag.StringVar(&formatOutput, "format", getEnvOr("SEC_FEED_OUTPUT_FORMAT", defaultOutputFormatting), "a formatting string for the resulting output data")
	flag.Parse()

	if *help {
		printHelp()
		os.Exit(0)
	}

	absoluteCacheFilePath := filepath.Join(cachePath, cacheFile)
	filters, err := WalkAllFilesInFilterDir(filepath.Clean(confPath))
	if err != nil {
		log.Fatal("failed to vulnerability filters.")
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "new":
		feed, cached, err := fetch_feed(feedUrl, absoluteCacheFilePath)
		if err != nil {
			log.Fatal(err)
		}
		cmdNewItems(feed, absoluteCacheFilePath, filters, cached)

	case "":
		log.Fatal("command not specified")
	default:
		log.Fatalf("invalid command: %s", cmd)
	}
}
