Contributing to Yara-Forensics
==============================

#### Table Of Contents

[How Can I Contribute?](#how-can-i-contribute)
  * [Reporting Bugs](#reporting-bugs)
  * [Suggesting Enhancements](#suggesting-enhancements)
  * [Your First Code Contribution](#your-first-code-contribution)
  * [Pull Requests](#pull-requests)

[Styleguides](#styleguides)
  * [Git Commit Messages](#git-commit-messages)

## How Can I Contribute?

### Reporting Bugs

We are using Travis CI to validate every pull requests as well as every merge to the master branch executes Yara correctly. Although we are using Travis CI, we can make mistakes that Travis may not recognize so feel free to send an [issue](https://github.com/Xumeiquer/yara-forensics/issues) and we (or someone else) will solve it.

When submiting a bug please try ti set the label `bug` to the issue.

### Suggesting Enhancements

On the other hand, you can suggest enhancements for the project as well as for the rules. Any comment you would like to suggest please send us an [issue](https://github.com/Xumeiquer/yara-forensics/issues) with the label `enhancements` and we will dicuss about it.

### Your First Code Contribution

This project has no code, but it has rules. The rules are been written in Yara language. It is very simple and you can have a look at [Yara documentation](http://yara.readthedocs.io/en/v3.5.0/). Once you got familiar with the Yara language you'll be ready to start writing rules.

We have split up the repository in two main folders, `file` and `raw`. The rules inside each folder are basically the same, the big difference is where Yara will find the magics. The rules in `file` are designed to find the magic headers at the beginning of the file. On the other hand, the rules in `raw` folder look for magics at any position in the file.

The simple rule for `file` rules is as following:

```
rule win_register: REG SUD
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {52 45 47 45 44 49 54}

    condition:
       $a at 0
}
```

And the simple rule for `raw` is as following:

```
rule win_register: REG SUD
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {52 45 47 45 44 49 54}

    condition:
       $a
}
```

The difference is at the *condition secction*.

As you may noticed we add `REG` and `SUD` next to the rule name. Those are yara *tags* and they are useful for executing specific rules when there is a need so we encourage you to do it as well, because you will ease someone's live when running this rule set.


**Advance rules**

Some magic headers are composed by several parts and the have to meet some conditions as the order they appear in the file, p.e. [pdf magics](file/pdf.yar).

For those kind of rules you must to write the condition in the correct order, otherwise the rule won't match properly.

For example in the pdf rule we have one header ($a) and three possible footers ($b, $c, and $d) so the condition looks like `$a at 0 and for any of ($b, $c, $d): (@ > @a)`. The $a has to be at offset 0x0 and footers ($b, $c, and $d) must be behind $a. The expression for that is `for any of ($b, $c, $d): (@ > @a)`.

The full pdf rules is as following:

```
rule pdf: PDF
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {25 50 44 46}
        $b = {0A 25 25 45 4F 46 (??|0A)}
        $c = {0D 0A 25 25 45 4F 46 0D 0A}
        $d = {0D 25 25 45 4F 46 0D}

    condition:
       $a at 0 and for any of ($b, $c, $d): (@ > @a)
}
```

Just remember when writing the `raw` rules the header, usually $a, can be at any position.


### Pull Requests

Onece you have finished writing your rules you can share them with the comunity. To achieve that we have a `devel` branch where we expect all pull request coming in so you have two options to do that.

**Forking the repository**

You can fork Yara-forensics on your Github profile and write your rules in there, usually in the master branch, when you are happy with your changes you have to generate a pull request from your `master` branch to our `devel` branch (see compare across forks), otherwise it won't work. When you get at this point Travis CI will trigger a build to check whether rules are Yara complaint. If everything goes well your pull request will be ready to be merged.

**Cloning the repository**

Other way to do a pull request is doing it from your computer. You will have to follow these steps:

1. Clone Yara-forensics on you computer.
1. Write your rules.
1. Run `runTest.sh`
1. Commit changes on your repository.
1. Push new content to your repository as well.
1. Generate a pull request from your repository to yara-forensics repository.
  1. Remember, you have to generate the pull request to the `devel` branch un yara-forensics

When you get at this point Travis CI will trigger a build to check whether rules are Yara complaint. If everything goes well your pull request will be ready to be merged.

NOTE: _In terms to run `runTest.sh` you have to have Yara installed in your system._

## Styleguides

### Git Commit Messages

Well, we haven't defined any style commit message yet, but normaly it summarizes the work you are sharing so any meaningful message will be useful.
