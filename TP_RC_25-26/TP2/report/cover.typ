// cover.typ

// cover.typ (Opção 3 - Barra Total)
#let capa(titulo: "", uc: "", sigla: "", grupo: "", ano: "", alunos: ()) = {
  set page(
    numbering: none,
    margin: (left: 4.5cm, right: 3cm, top: 4cm, bottom: 3cm),
  )

  // A barra lateral
  place(
    left,
    dx: -4.5cm,
    dy: -4cm,
    rect(
      width: 2.5cm,
      height: 100% + 7cm,
      fill: rgb("#263238"),
    )
  )

  // Sigla no canto inferior direito
  place(
    bottom + right,
    text(size: 80pt, weight: "bold", fill: rgb("#263238"))[#sigla]
  )

  set align(left)

  // Conteúdo da Capa
  stack(
    dir: ltr,
    image("imgs/UM.jpg", width: 26mm),
    image("imgs/EE.jpg", width: 26mm),
  )

  v(7mm)
  block(spacing: 17pt)[
    #text(size: 14.4pt, weight: "bold")[Universidade do Minho] \
    #text(size: 14.4pt, weight: "light")[Escola de Engenharia]
  ]

  v(50mm)
  block(spacing: 27pt)[
    #text(size: 20pt, weight: "bold")[#uc] \
    #text(size: 20pt)[#titulo]
  ]

  v(1.5em)
  text(size: 17pt)[
    Licenciatura em Engenharia Informática \
    Ano Letivo #ano
  ]

  v(22mm)
  text(size: 14.4pt)[
    #grid(
      columns: (25mm, auto),
      row-gutter: 15pt,
      grid.cell(colspan: 2)[#strong[Grupo #grupo]],
      ..alunos.map(a => ([#a.id], [#a.nome])).flatten()
    )
  ]

  v(1fr)
  pagebreak()
}
