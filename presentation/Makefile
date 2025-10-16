.PHONY: all clean watch

PDF = gemini-exfil-detection.pdf
TEX = gemini-exfil-detection.tex

all: $(PDF)

$(PDF): $(TEX)
	tectonic $(TEX)

watch:
	@echo "Watching for changes..."
	@while true; do \
		inotifywait -e modify $(TEX) 2>/dev/null || \
		fswatch -1 $(TEX) 2>/dev/null || \
		(echo "Install fswatch or inotifywait for watch mode" && exit 1); \
		make all; \
	done

clean:
	rm -f *.aux *.log *.nav *.out *.snm *.toc *.vrb *.pdf

open: $(PDF)
	open $(PDF) || xdg-open $(PDF) || start $(PDF)

.DEFAULT_GOAL := all
