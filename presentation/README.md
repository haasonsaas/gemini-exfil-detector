# BSides Presentation

This directory contains the LaTeX Beamer presentation for the Gemini Exfil Detector.

## Compiling the Presentation

### Using Tectonic (Recommended)

Tectonic is a modern, self-contained LaTeX engine that automatically downloads dependencies.

**Install:**
```bash
# macOS
brew install tectonic

# Linux
curl --proto '=https' --tlsv1.2 -fsSL https://drop-sh.fullyjustified.net | sh

# Windows
https://tectonic-typesetting.github.io/
```

**Compile:**
```bash
cd presentation
tectonic gemini-exfil-detection.tex
```

This will generate `gemini-exfil-detection.pdf`.

### Using Traditional LaTeX

If you have a full LaTeX distribution installed (TeX Live, MacTeX):

```bash
cd presentation
pdflatex gemini-exfil-detection.tex
pdflatex gemini-exfil-detection.tex  # Run twice for references
```

## Presentation Structure

- **The Problem**: Insider threat landscape and LLM-assisted reconnaissance
- **The Detection**: Correlation logic, recon signals, exfil signals
- **Implementation**: Architecture, deployment options, example findings
- **Results & Insights**: Why it works, advantages, common patterns
- **Operational Considerations**: Deployment checklist, metrics, limitations
- **Conclusion**: Key takeaways and resources

## Customization

Edit `gemini-exfil-detection.tex` to:
- Change theme: `\usetheme{...}` (try Berlin, Copenhagen, Warsaw)
- Adjust aspect ratio: `\documentclass[aspectratio=169]{beamer}` (16:9) or `\documentclass[aspectratio=43]{beamer}` (4:3)
- Modify colors: `\usecolortheme{...}`
- Add your own slides

## Presentation Tips for BSides

1. **Time**: Target 20-25 minutes for talk + 5 min Q&A
2. **Audience**: Mix of defenders, researchers, and practitioners
3. **Focus**: Actionable takeaways - they should be able to deploy this
4. **Demo**: Consider live demo or pre-recorded video of finding generation
5. **Questions**: Be prepared to discuss false positive rates, cost, privacy implications

## Notes

- Font warnings during compilation are cosmetic and can be ignored
- The PDF is optimized for 16:9 widescreen displays
- Page count: ~25 slides (adjust presentation pace accordingly)
