package linkedinchallenge

import (
	"github.com/PuerkitoBio/goquery"
)

func extractValue(d *goquery.Document, selector string) string {
	s := d.Find(selector).First()
	if s == nil || s.Length() == 0 {
		return ""
	}

	v, _ := s.Attr("value")
	return v
}
