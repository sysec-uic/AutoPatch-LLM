joern-scan first generates a complete cpg of the input code.
Next it traverses through the graph to locate nodes which match certain attributes.
For example in one use after free query it will match any method nodes that call the function free() and further filters those results to find functions where the vulnerability exists.
Here is a reference query:

```
withStrRep({ cpg =>
        cpg.method
          .name("(.*_)?free")
          .filter(_.parameter.size == 1)
          .callIn
          .where(_.argument(1).isIdentifier)
          .flatMap(f => {
            val freedIdentifierCode = f.argument(1).code
            val postDom             = f.postDominatedBy.toSetImmutable

            val assignedPostDom = postDom.isIdentifier
              .where(_.inAssignment)
              .codeExact(freedIdentifierCode)
              .flatMap(id => Iterator.single(id) ++ id.postDominatedBy)

            postDom
              .removedAll(assignedPostDom)
              .isIdentifier
              .codeExact(freedIdentifierCode)
          })
      }),
```
