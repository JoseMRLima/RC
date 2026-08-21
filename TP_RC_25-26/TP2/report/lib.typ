// lib.typ
#let conf(
  titulo: "",
  uc: "",
  sigla: "",
  grupo: "",
  ano: "",
  alunos: (),
  doc,
) = {
  // --- Configurações de Página e Texto ---
  set page(
    paper: "a4",
    margin: (left: 3cm, right: 3cm, top: 3cm, bottom: 3cm),
  )
  
  set text(font: "PT Sans", lang: "pt", size: 11pt)

  // --- Regras de Formatação Automática ---
  set heading(numbering: "1.1.")
  set figure(gap: 1.5em)
  
  // Estilo para Blocos de Código
  show raw: set text(font: "Cascadia Code", size: 9pt)
  show raw.where(block: true): it => block(
    fill: rgb("#f5f5f5"),
    inset: 10pt,
    radius: 4pt,
    width: 100%,
    it
  )

  // --- Configuração de Espaçamento dos Títulos ---
  show heading: it => {
    // Espaço antes do título (exceto se for o primeiro da página)
    v(1.5em, weak: true)
    
    it
    
    // Espaço depois do título (antes do parágrafo)
    v(0.8em, weak: true)
  }

  // Opcional: Aumentar o espaçamento entre parágrafos
  set par(
    justify: true,
    leading: 0.65em,     // Espaço entre linhas
    spacing: 1.2em      // Espaço entre parágrafos diferentes
  )

  // Estilo para Equações (Centradas e com numeração)
  set math.equation(numbering: "(1)")

  // 1. Gerar a Capa
  import "cover.typ": capa
  capa(titulo: titulo, uc: uc, sigla: sigla, grupo: grupo, ano: ano, alunos: alunos)

  // 2. Índice (Table of Contents)
  set page(numbering: "i") // Numeração romana para o índice
  counter(page).update(1)
  
  // 3. Conteúdo Principal
  set page(numbering: "1") // Numeração árabe para o conteúdo
  counter(page).update(1)

  show outline.entry.where(level: 1): it => {
    v(1.2em, weak: true) // Espaço extra antes de capítulos principais
    strong(it)
  }

  set outline(
    title: [Índice],
    indent: 2em,
  )

  outline()
  pagebreak()
  
  doc
}
