# pyscan como hook de pre-commit / CI

Convierte pyscan en una barrera automática: cada vez que alguien modifica un
`requirements.txt`, se analizan las dependencias y **se bloquea el commit** si
alguna resulta maliciosa o sospechosa de typosquatting. Responde directamente a
la pregunta del director: *"que cuando una persona meta una librería que no es,
mande alerta"*.

Es una capa delgada sobre el CLI: reutiliza el mismo motor y sus códigos de
salida (0 = limpio, ≠ 0 = bloquea). No cambia la arquitectura.

## Requisitos

- Tener pyscan instalado (`pip install -e .`) y el framework
  [pre-commit](https://pre-commit.com): `pip install pre-commit`.

## Opción A — usar pyscan como hook remoto

En el proyecto que quieres proteger, crea `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://dev.azure.com/jdgutierrez017/Tesis/_git/Tesis
    rev: main            # o una etiqueta/commit fijo
    hooks:
      - id: pyscan
```

Instala el hook:

```bash
pre-commit install
```

Desde ahora, al hacer `git commit` tras cambiar un `requirements.txt`, pyscan lo
revisa. Para correrlo a mano sobre todo el repositorio:

```bash
pre-commit run pyscan --all-files
```

## Opción B — hook local (sin repositorio remoto)

Si prefieres no depender del repo remoto, define un hook local:

```yaml
repos:
  - repo: local
    hooks:
      - id: pyscan
        name: pyscan - dependencias maliciosas
        entry: pyscan precommit
        language: system
        files: (^|/)requirements.*\.txt$
        pass_filenames: true
```

## Uso directo (sin pre-commit)

El mismo comando sirve en cualquier pipeline de CI:

```bash
pyscan precommit requirements.txt
echo $?          # 0 = limpio, 1 = bloqueado (hay riesgo)
```

También puedes usar el comando general con salida SARIF para plataformas como
GitHub Advanced Security o Azure DevOps:

```bash
pyscan scan -r requirements.txt --sarif pyscan.sarif
```

## Qué bloquea

- Paquetes que el clasificador marca como **MALICIOSO**.
- Nombres **sospechosos por typosquatting** (aunque el paquete no exista aún en
  PyPI), con la sugerencia del paquete legítimo más parecido.

Todo lo demás pasa sin fricción.
