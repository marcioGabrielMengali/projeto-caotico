# Docker Scout

O que é docker scout e o que é código CVE

## Commands

- ### Quickview

```bash
docker scout quickview marciogabriel1998/imagem-caotica:v1
```

Quickview para file system

```bash
docker scout quickview fs://.
```

---

- ### cves

```bash
docker scout cves marciogabriel1998/imagem-caotica:v1
```

```bash
docker scout cves --format markdown marciogabriel1998/imagem-caotica:v1
```

```bash
docker scout cves fs://.
```

---

- ### Repo

```bash
docker scout repo enable --org marciogabriel1998 marciogabriel1998/imagem-caotica
```
