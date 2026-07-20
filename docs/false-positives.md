# False Positives

Security scanners are useful only if their findings are explainable and fixable.

If Bulwark flags something that is safe in your setup, open an issue with:

- finding ID;
- server platform;
- Minecraft version;
- relevant config with secrets removed;
- why the condition is safe in your case;
- expected severity or whether it should not fire.

You can silence or re-rate findings locally in `plugins/Bulwark/config.yml`:

```yaml
ignore:
  - query-enabled

severity-overrides:
  no-whitelist: INFO
```

False-positive fixes take priority over adding new checks.
