# jq

## Beautify

```bash
jq '.' file.json
```

## Select a specific value

```bash
jq '.field' example.json
```

## Filter by a specific value:

```bash
jq '. | select(.field.anotherField == "valor")' archivo.json
```

## Iterate through elements in an array:

```bash
jq '.array[]' archivo.json
```

## Count elements in an array:

```bash
jq '.array | length' file.json
```

## Map and transform elements in an array:

```bash
jq '.array[] | .field' file.json
```

## Combine multiple selections:

```bash
jq '.field1, .field2' file.json
```

## Filter nested results:

```bash
jq '.array[].field' file.json
```

## Iterate through JSON objects:

```bash
jq 'to_entries[] | .key, .value' file.json
jq '.array[].field | "\(.value), \(.value)"' users.json
```