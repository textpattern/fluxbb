# FluxBB configuration used for Textpattern support forum

## Install

Work in progress, but the plan would be to allow use of Composer:

```ShellSession
$ composer create-project https://github.com/textpattern/fluxbb.git /
```

After which you would follow the standard [FluxBB installation steps](http://fluxbb.org/docs/v1.5/installing).

## Development

Development happens in the *feature-textpattern-forum* branch:

```ShellSession
$ git clone --branch feature-textpattern-forum git@github.com:textpattern/fluxbb.git
```

To create a patch:

```ShellSession
$ git diff master feature-textpattern-forum > feature-textpattern-forum.patch
```
