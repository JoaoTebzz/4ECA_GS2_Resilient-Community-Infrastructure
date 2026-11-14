// Funcoes comuns para montar os relatorios em .docx
const fs = require("fs");
const path = require("path");
const D = require("docx");
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, ImageRun, Header, Footer, AlignmentType,
  LevelFormat, HeadingLevel, BorderStyle, WidthType, ShadingType, PageNumber, PageBreak, TableOfContents } = D;

const ROOT = path.join(__dirname, "..");
const FONT = "Arial";
const W = 9638; // largura util A4 com margem de 2 cm (DXA)
const AZUL = "1F4E79";

const border = { style: BorderStyle.SINGLE, size: 4, color: "BBBBBB" };
const borders = { top: border, bottom: border, left: border, right: border };

// texto com **negrito**, `codigo` e [[campo para preencher]] (amarelo)
function runs(text, base = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\[\[[^\]]+\]\])/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(new TextRun({ text: text.slice(last, m.index), font: FONT, ...base }));
    const t = m[0];
    if (t.startsWith("**")) out.push(new TextRun({ text: t.slice(2, -2), bold: true, font: FONT, ...base }));
    else if (t.startsWith("`")) out.push(new TextRun({ text: t.slice(1, -1), font: "Consolas", size: (base.size || 22) - 2, ...base, shading: { type: ShadingType.CLEAR, fill: "F0F0F0" } }));
    else out.push(new TextRun({ text: "[" + t.slice(2, -2) + "]", font: FONT, highlight: "yellow", ...base }));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(new TextRun({ text: text.slice(last), font: FONT, ...base }));
  return out;
}

const P = (text, opts = {}) => new Paragraph({ children: runs(text, opts.run || {}), spacing: { after: 120, line: 300 }, alignment: opts.align, keepNext: opts.keepNext, ...(opts.p || {}) });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: t, font: FONT })] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun({ text: t, font: FONT })] });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun({ text: t, font: FONT })] });
const B = (text, level = 0) => new Paragraph({ numbering: { reference: "bul", level }, children: runs(text), spacing: { after: 60, line: 290 } });
const N = (text, ref = "num") => new Paragraph({ numbering: { reference: ref, level: 0 }, children: runs(text), spacing: { after: 60, line: 290 } });
const SP = () => new Paragraph({ children: [], spacing: { after: 80 } });
const BR = () => new Paragraph({ children: [new PageBreak()] });

function CODE(lines) {
  return lines.map((l, i) => new Paragraph({
    children: [new TextRun({ text: l === "" ? " " : l, font: "Consolas", size: 17 })],
    shading: { type: ShadingType.CLEAR, fill: "F3F3F3" },
    spacing: { after: 0, line: 240 },
    border: i === 0 ? { top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 4 } } : undefined,
  }));
}

function TABLE(headers, rows, widths, opts = {}) {
  const total = widths.reduce((a, b) => a + b, 0);
  const fs = opts.size || 18;
  const mk = (txt, w, head, fill) => new TableCell({
    width: { size: w, type: WidthType.DXA }, borders,
    shading: head ? { type: ShadingType.CLEAR, fill: AZUL } : fill ? { type: ShadingType.CLEAR, fill } : undefined,
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children: String(txt).split("\n").map((line) => new Paragraph({ children: runs(line, head ? { bold: true, color: "FFFFFF", size: fs } : { size: fs }), spacing: { after: 20, line: 250 } })),
  });
  return new Table({
    width: { size: total, type: WidthType.DXA }, columnWidths: widths,
    rows: [
      new TableRow({ tableHeader: true, cantSplit: true, children: headers.map((h, i) => mk(h, widths[i], true)) }),
      ...rows.map((r, ri) => new TableRow({ cantSplit: true, children: r.map((c, i) => mk(c, widths[i], false, ri % 2 ? "F5F8FC" : null)) })),
    ],
  });
}

function IMG(file, wPx, hPx, caption) {
  const data = fs.readFileSync(path.join(ROOT, "figs", file));
  const out = [new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 80, after: 40 }, keepNext: true,
    children: [new ImageRun({ type: "png", data, transformation: { width: wPx, height: hPx }, altText: { title: caption, description: caption, name: file } })] })];
  if (caption) out.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 }, children: [new TextRun({ text: caption, italics: true, size: 18, font: FONT, color: "555555" })] }));
  return out;
}

function cover(titulo, sub, idEntregavel) {
  return [
    new Paragraph({ spacing: { before: 1800, after: 120 }, children: [new TextRun({ text: "FIAP", bold: true, color: "ED145B", size: 36, font: FONT }), new TextRun({ text: "   Global Solution 2026.2 · Cybersecurity", size: 22, font: FONT, color: "555555" })] }),
    new Paragraph({ spacing: { before: 600, after: 120 }, children: [new TextRun({ text: titulo, bold: true, size: 52, font: FONT, color: AZUL })] }),
    new Paragraph({ spacing: { after: 600 }, children: [new TextRun({ text: sub, size: 28, font: FONT, color: "333333" })] }),
    TABLE(["Item", "Informação"], [
      ["Desafio", "Resilient Community Infrastructure (Rede Comunitária Vila Aurora)"],
      ["Entregável", idEntregavel],
      ["Professor", "Prof. Carlos Eduardo de Siqueira"],
      ["Integrantes", "[[Nome 1 (RM)]]\n[[Nome 2 (RM)]]\n[[Nome 3 (RM)]]"],
      ["Turma e grupo", "[[Turma]] · [[Grupo]]"],
      ["Data", "Novembro de 2026"],
      ["Repositório", "[[link do repositório Git]]"],
    ], [2200, 7438], { size: 20 }),
  ];
}

function build(title, children, outFile) {
  const doc = new Document({
    creator: "Grupo GS2026.2", title,
    styles: {
      default: { document: { run: { font: FONT, size: 22 } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 32, bold: true, font: FONT, color: AZUL }, paragraph: { spacing: { before: 360, after: 140 }, keepNext: true, outlineLevel: 0 } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 26, bold: true, font: FONT, color: "2E5E8E" }, paragraph: { spacing: { before: 240, after: 100 }, keepNext: true, outlineLevel: 1 } },
        { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 23, bold: true, font: FONT, color: "333333" }, paragraph: { spacing: { before: 180, after: 80 }, keepNext: true, outlineLevel: 2 } },
      ],
    },
    numbering: { config: [
      { reference: "bul", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } },
                                   { level: 1, format: LevelFormat.BULLET, text: "◦", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1000, hanging: 270 } } } }] },
      ...["num", "num2", "num3"].map((r) => ({ reference: r, levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 300 } } } }] })),
    ] },
    sections: [{
      properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1300, right: 1134, bottom: 1200, left: 1134 } } },
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 4 } }, children: [new TextRun({ text: "FIAP", bold: true, color: "ED145B", size: 18, font: FONT }), new TextRun({ text: "  ·  Global Solution 2026.2  ·  Resilient Community Infrastructure", size: 18, font: FONT, color: "777777" })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: title + "  ·  Página ", size: 16, font: FONT, color: "777777" }), new TextRun({ children: [PageNumber.CURRENT], size: 16, font: FONT, color: "777777" }), new TextRun({ text: " de ", size: 16, font: FONT, color: "777777" }), new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 16, font: FONT, color: "777777" })] })] }) },
      children,
    }],
  });
  return Packer.toBuffer(doc).then((b) => { fs.writeFileSync(outFile, b); console.log("gerado", outFile); });
}

const R = (n) => JSON.parse(fs.readFileSync(path.join(ROOT, "results", n + ".json"), "utf8"));
const brl = (v) => "R$ " + v.toLocaleString("pt-BR");

module.exports = { D, P, H1, H2, H3, B, N, SP, BR, CODE, TABLE, IMG, cover, build, R, brl, ROOT, W, TableOfContents };
