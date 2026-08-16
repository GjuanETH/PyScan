# Subir pyscan a Azure DevOps (Repos)

Esta guía te deja el proyecto versionado en **Azure DevOps** y te permite ir
subiendo cada avance. Solo se hace la configuración una vez; después, subir un
avance es un clic.

> ¿Por qué tú y no Claude? El push necesita **tus credenciales** (un token
> personal) y acceso de red a tu organización; eso debe quedarse en tu equipo.

---

## Requisito: tener Git instalado (una sola vez)

Descárgalo de https://git-scm.com/download/win e instálalo con las opciones por
defecto. (En la instalación se incluye *Git Credential Manager*, que recordará tu
acceso para no pedírtelo cada vez.)

---

## Paso 1 — Crear el repositorio vacío en Azure DevOps

1. Entra a tu proyecto en https://dev.azure.com → menú **Repos**.
2. Si no tienes uno para esto, crea un repositorio nuevo llamado **`pyscan`**
   (arriba, en el selector de repos → *New repository*).
   - **No** marques "Add a README" (el proyecto ya trae los suyos).
3. Copia la **URL de clonado** que te muestra: algo como
   `https://dev.azure.com/TU_ORG/TU_PROYECTO/_git/pyscan`

## Paso 2 — Crear un Personal Access Token (PAT)

Azure DevOps no usa tu contraseña normal para git, sino un **token**:

1. En Azure DevOps, arriba a la derecha: **User settings** (icono) → **Personal access tokens**.
2. **New Token** → nombre `pyscan-git`, organización la tuya, expiración a tu gusto.
3. En *Scopes*, marca **Code → Read & Write**. Crea el token y **cópialo**
   (no se vuelve a mostrar).
4. Cuando git te pida usuario/contraseña al subir, usa tu email como usuario y
   **pega el token como contraseña**. Git Credential Manager lo recordará.

## Paso 3 — Subir (la forma fácil)

Haz **doble clic en `subir_a_azure.bat`** (está en la carpeta `pyscan`). El script:

1. Inicializa el repositorio si hace falta.
2. La primera vez te pide la **URL** del Paso 1.
3. Te pide un **mensaje** describiendo el avance.
4. Sube todo a Azure DevOps.

A partir de ahí, cada vez que quieras guardar un avance, vuelves a hacer doble
clic, escribes el mensaje y listo.

---

## (Alternativa) Hacerlo a mano en PowerShell

La primera vez, dentro de la carpeta `pyscan`:

```powershell
git init
git branch -M main
git config user.name "Andres Felipe Sanguino Cubillos"
git config user.email "jdgutierrez017@ucatolica.edu.co"
git remote add origin https://dev.azure.com/TU_ORG/TU_PROYECTO/_git/pyscan
git add .
git commit -m "Sprint 1-3: fetcher, extractores de metadatos y entropía, CLI y pruebas"
git push -u origin main
```

Para cada avance siguiente:

```powershell
git add .
git commit -m "Describe el avance aquí"
git push
```

---

## Sugerencia de mensajes de commit (uno por avance)

- `Sprint 1-2: fetcher seguro + extractor de metadatos (typosquatting) + CLI`
- `Sprint 3: extractor de entropía de Shannon con ventana deslizante`
- `Sprint 4: extractor AST (pendiente)`
- `Sprint 5: clasificador ML + dataset (pendiente)`

> Nota: si al ejecutar el `.bat` ves un aviso sobre una carpeta `.git` parcial,
> es normal: el script la limpia solo. Esa carpeta quedó de un intento previo y
> no afecta nada.
