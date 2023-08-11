---
title: Privilege Escalation in AWS - Part 02
author:
date: 2023-08-08 22:00:00 +0500
comments: false
categories: [Cloud-Security, AWS]
tags: [cloud security, aws] # TAG names should always be lowercase
image:
  path: /assets/img/posts/aws-priv-esc-02/01.png
  alt: Credits to @rez0 for this image
---

## Background

This blog post is part of the AWS privilege escalation series. If you have not already, I would suggest checking out the previous post: [Privilege Escalation in AWS - Part 01](https://mystic0x1.github.io/posts/AWS-Privilege-Escalation-Part-01/)

In this post we will talk about the types of Identity-based policies in AWS and how some permissions related to these policies can lead to privilege escalation. In AWS, there are 3 types of Identity-based policies:

- **AWS Managed Policy:** As the name suggest, AWS-managed policies are created and administered by AWS itself. These are predefined policies provided by AWS to cater to various use cases. An example of this is the [ReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html) policy.

- **Customer Managed Policy:** Managed Policies like the one explained above but defined by customer/user. Unlike AWS Managed Policies, a user with permissions can create or update these policies. 

> A Managed Policy is an standalone object, that can be attached with multiple principals (users, groups, roles). Change in the policy will affect all the resources to which this policy is attached to.
{: .prompt-info }

- **Inline Policy:** A custom policy created by users for one specific principal i.e., a user, a group, or a role. Directly linked/embedded with the principal; if the principal is removed, the inline policy will also get removed automatically.

In the rest of this article, when we say `managed` policy, we will be referring to both, the `AWS` and `Customer` managed policies.

With the difference between these policies being clear now, let's jump into the fun part:

## IAM-AttachUserPolicy
The `IAM-AttachUserPolicy` permission allow a principal to attach a `managed` policy to a user (defined in the policy document).

> Note that we are saying `managed` policies, which include both the AWS and customer-managed policies.
{: .prompt-info }

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-AttachUserPolicy` permission for our compromised user or any user that we have access to.

### Enumeration
So, we have compromised a user who can list other resources in this environment. We will start by listing different roles and finding which one we can assume. We can list specific roles, and once we are sure that we can assume them, we will then proceed to check their permissions:

```bash
aws iam get-role --role-name privesc7-AttachUserPolicy-role
```

![](/assets/img/posts/aws-priv-esc-02/case-07-01-Get-Role.png)
_Get Details of a specific role_

Our compromised user is listed under the `principal` property which means we can assume this role. Let's find out what this role is capable of. For this, we will list down the attached policies of this role:

```bash
# list attached policies of a role:
aws iam list-attached-role-policies --role-name privesc7-AttachUserPolicy-role

# Get policy document of specified policy:
aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc7-Attac hUserPolicy --version-id v1
```

![](/assets/img/posts/aws-priv-esc-02/case-07-02-Get-Policy-Document.png)
_Get policy document_

> Fawaz, you mentioned managed and inline policies. So what type of policy is this that we just listed, you ask? 
> 
> Well this is managed policy. The command `list-attached-role-policies` lists the managed policies that are attached to the specified role.
{: .prompt-tip }

A quick review of the policy document shows that this role has the permission `iam:AttachUserPolicy` over **ALL** Users!

### Privilege Escalation
I think you know what you, as an adversary, would do here. Having this permission means this role can attach any managed policy to any user. So we can attach the AWS Managed Policy, [AdministratorAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html) to our compromised user (or any user for that matter) to give them full access.

```bash
aws iam attach-user-policy --user-name purple --policy-arn arn:aws:iam::aws:policy/AdministratorAccess  --profile privesc7
```

![](/assets/img/posts/aws-priv-esc-02/case-07-03-AttachingUserPolicy.png)
_Attaching AdministratorAccess policy to a user_

> Fawaz, how can I distinguish between an AWS-managed policy and a customer-managed policy, you ask?
>
> Look at the ARN of the policies. For AWS managed policy, in place of `account-ID` you will see the string `aws`. For customer-managed policy, it will be `account-ID`.
{: .prompt-tip }

With this policy attached to our user, we have full access to the environment.

## IAM-AttachGroupPolicy
The `IAM-AttachGroupPolicy` permission allow a principal to attach a `managed` policy to a group (defined in the policy document).

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-AttachGroupPolicy` permission for a group that includes our compromised user.

### Enumeration
Starting with the enumeration of roles, we find out that `privesc8-AttachGroupPolicy-role` is the one that we can assume:

```bash
aws iam get-role --role-name privesc8-AttachGroupPolicy-role
```

![](/assets/img/posts/aws-priv-esc-02/case-08-01-Get-Role.png)
_Get details of the specified role_

Our next step would be to list down the policy document of the attached policy to see what we can do via this role:

```bash
aws iam list-attached-role-policies --role-name privesc8-AttachGroupPolicy-role

aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc8-Attac hGroupPolicy --version-id v1
```

![](/assets/img/posts/aws-priv-esc-02/case-08-02-Get-Policy-Document.png)
_Get policy document_

According to the policy document, this role has `iam:AttachGroupPolicy` permissions over **ALL** groups.

### Privilege Escalation
So, we can attach a managed policy to any group now. The next logical step here is to find out what groups our compromised user is part of. 

Let's say the name of our compromised user is `privesc8-AttachGroupPolicy-user`. In that case, we can list their groups and then the policies attached to them using the following commands:

```bash
# List groups of specified user:
aws iam list-groups-for-user --user-name privesc8-AttachGroupPolicy-user

# List policies attached to the specified group
aws iam list-attached-group-policies --group-name privesc8-AttachGroupPolicy-group
```

![](/assets/img/posts/aws-priv-esc-02/case-08-03-Getting-Details-of-Our-Groups.png)
_Get details of groups for a specific user_

Our compromised user is part of the `privesc8-AttachGroupPolicy-group` group which does not have any policy attached to them... yet :)

Since we know the group we are part of, let's attach the same old `AdministratorAccess` policy to have full access:

```bash
aws iam attach-group-policy --group-name privesc8-AttachGroupPolicy-group --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile privesc8
```

![](/assets/img/posts/aws-priv-esc-02/case-08-04-Attaching-Group-Policy-and-Checking.png)
_Attaching AdministratorAccess Policy to a specified group_

If you see the 2nd command in the above image, our group now has an `AdministratorAccess` policy attached which eventually means our compromised user (and any user who is part of this group) has elevated privileges now.

## IAM-AttachRolePolicy
The `IAM-AttachRolePolicy` permission allow a principal to attach a `managed` policy to a role (defined in the policy document).

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-AttachRolePolicy` permission for the role itself or any other role that our compromised user can assume.

### Enumeration
We will list down the roles and find out which one we can assume, and then we can get the policy document for that role to see what permissions are assigned to it:

```bash
aws iam get-role --role-name privesc9-AttachRolePolicy-role
```

![](/assets/img/posts/aws-priv-esc-02/case-09-01-Get-Role.png)
_Get details of the specified role_

```bash
aws iam list-attached-role-policies --role-name privesc9-AttachRolePolicy-role

aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc9-AttachRolePolicy --version-id v1
```

![](/assets/img/posts/aws-priv-esc-02/case-09-02-Get-Policy-Document.png)
_Get policy document_

As per the policy document, this role can attach managed policies to any role.

### Privilege Escalation
Having this capability, we can follow either of the following approaches to exploit this misconfiguration:

- Attaching the `AdministratorAccess` policy to this role itself.
- Find another role that our compromised user can assume and attach the `AdministratorAccess` policy to that role.

Let's go with the first approach i.e, attaching the policy to this (`privesc9-AttachRolePolicy-role`) role itself:

```bash
aws iam attach-role-policy --role-name privesc9-AttachRolePolicy-role --policy-arn arn: aws:iam::aws:policy/AdministratorAccess --profile privesc9
```

![](/assets/img/posts/aws-priv-esc-02/case-09-03-Attach-Role-Policy.png)
_Attach administratoraccess policy to the specified role_

Now the `privesc9-AttachRolePolicy-role` has another policy attached to it permitting this role to perform any action on any resource. Since we can already assume it, we have elevated our privileges. We can quickly verify that the `AdministratorAccess` policy was attached:

```bash
aws iam list-attached-role-policies --role-name privesc9-AttachRolePolicy-role
```

![](/assets/img/posts/aws-priv-esc-02/case-09-04-Get-Attached-Policies-Again.png)
_List attached policies_

---
---

> So far we have talked about permissions that allow any principal to attach `managed` policies to different resources (users, groups, and roles). Next, we will be exploring some permissions that could lead to privilege escalation via using `inline` policies.
{: .prompt-info }

## IAM-PutUserPolicy
The `iam-PutUserPolicy` allow a principal to add (or update) an inline policy to a user.

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-PutUserPolicy` permission for our compromised user or any user that we have access to.

### Enumeration
You must be familiar with this phase by now :) Let's start by listing roles to find out which one our compromised user can assume:

```bash
aws iam get-role --role-name privesc10-PutUserPolicy-role
```

![](/assets/img/posts/aws-priv-esc-02/case-10-01-Get-Role.png)
_Get details of the specified role_

Next, we will list the attached policies to this role and then get the policy document to find out what this role is capable of:

```bash
aws iam list-attached-role-policies --role-name privesc10-PutUserPolicy-role

aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc10-PutUserPolicy --version-id v1
```

![](/assets/img/posts/aws-priv-esc-02/case-10-02-Get-Policy-Document.png)
_Get policy document_

By reading through the policy document, we find out that this role has permission to add (or update) inline policies to any user.

> But Fawaz, how can I distinguish if the permission is for `managed` policies or `inline`?
>
> Whelp, for `managed` policies, the permissions are `iam-Attach*Policy`, and for `inline` policies it is `iam-Put*Policy`. Similarly, to list these policies we use `list-attached-*-policies` for `managed` and `list-*-policies` for `inline` policies, where `*` can be `user`, `group`, or `role`.
{: .prompt-tip }

### Privilege Escalation
Having this permission, we can add/put an inline policy to our compromised users to give them elevated privileges in the environment. But before that, let's first list down the `inline` policies (if any) of our compromised user:

```bash
aws iam list-user-policies --user-name privesc10-PutUserPolicy-User
```

![](/assets/img/posts/aws-priv-esc-02/case-10-03-Get-Inline-Policy-of-Our-User.png)
_List inline policies of the specified user_

So right now our user does not have any inline policy embedded. Let's do that, shall we?

```bash
aws iam put-user-policy --user-name privesc10-PutUserPolicy-User --policy-name privesc-admin-policy --policy-document file:///policies/admin-policy.json
```
![](/assets/img/posts/aws-priv-esc-02/case-10-04-Put-User-Policy.png)
_Adding inline policy to the specified user_

We have added an inline policy to our user with a custom policy document. The policy document allows full access to the user:

![](/assets/img/posts/aws-priv-esc-02/case-10-05-Admin-Policy-Doc.png)
_Content of custom admin policy document_

Having this inline policy, our compromised user has full access to the target environment now.

## IAM-PutGroupPolicy
The `iam-PutGroupPolicy` allow a principal to add (or update) an inline policy to a group.

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-PutGroupPolicy` permission for a group of which our compromised user is a member.

### Enumeration
Verifying the details of the role which our user can assume:

```bash
aws iam get-role --role-name privesc11-PutGroupPolicy-role
```

![](/assets/img/posts/aws-priv-esc-02/case-11-01-Get-Role.png)
_Get details of the specified role_

Next, we will list the attached policies to this role and then get the policy document to find out what this role is capable of:

```bash
aws iam list-attached-role-policies --role-name privesc11-PutGroupPolicy-role

aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc11-PutGroupPolicy --version-id v1
```

![](/assets/img/posts/aws-priv-esc-02/case-11-02-Get-Policy-Document.png)
_Get policy document_

As per this policy document, this role has permission to add (or update) inline policies to any group.

### Privilege Escalation
So, we can put inline policies for any group. The next logical step here is to find out what groups our compromised user is part of. 

Let's say the name of our compromised user is `privesc11-putgrouppolicy-user`. In that case, we can list their groups and then put an inline policy using the following commands:

```bash
# List groups of the specified user
aws iam list-groups-for-user --user-name privesc11-putgrouppolicy-user

# Put inline policy to the specified group
aws iam put-group-policy --group-name privesc11-PutGroupPolicy-group --policy-name empty_inline_policy --policy-document file:///home/mystic/admin-policy.json --profile privesc11
```

![](/assets/img/posts/aws-priv-esc-02/case-11-03-Put-Group-Policy.png)
_Adding inline policy to the specified group_

The policy document used here is the same as described in the previous scenario. With this, our user who is part of the `privesc11-PutGroupPolicy-group` group has elevated privileges.


## IAM-PutRolePolicy
The `iam-PutRolePolicy` allow a principal to add (or update) an inline policy to a role.

### Assumptions
- We have compromised a user who has read-only access in the target environment.
- This user can assume a role that has `IAM-PutRolePolicy` permission for a role that our compromised user can assume.

### Enumeration
Verifying the details of the role which our user can assume:

```bash
aws iam get-role --role-name privesc12-PutRolePolicy-role
```

![](/assets/img/posts/aws-priv-esc-02/case-12-01-Get-Role.png)
_Get details of the specified role_

Next, we will list the attached policies to this role and then get the policy document to find out what this role is capable of:

```bash
aws iam list-attached-role-policies --role-name privesc12-PutRolePolicy-role

aws iam get-policy-version --policy-arn arn:aws:iam::xxxxxxxxxxxx:policy/privesc12-PutRolePolicy --version-id v1
```

![](/assets/img/posts/aws-priv-esc-02/case-12-02-Get-Policy-Document.png)
_Get policy document_

Reading through this policy document, we find out that this role has permission to add (or update) inline policies to any role.

### Privilege Escalation
To exploit this misconfiguration, we can either put an inline policy to the current role itself or choose another role that our user can assume. We will go with the current role, `privesc12-PutRolePolicy-role`.

We will first list the current inline policies (which shows currently there are none) of this role. Then we will proceed by adding a new inline policy to this role with our `admin-policy.json` policy document:

```bash
# List inline policies of the specified role
aws iam list-role-policies --role-name privesc12-PutRolePolicy-role

# Put inline policy to the specified role
aws iam put-role-policy --role-name privesc12-PutRolePolicy-role --policy-name new_inline_policy --policy-document file:///home/mystic/admin-policy.json --profile privesc12
```

![](/assets/img/posts/aws-priv-esc-02/case-12-03-Put-Role-Policy.png)
_Adding inline policy to the specified role_

As it is evident from the image above, the role `privesc12-PutRolePolicy-role` has a new inline policy now allowing it to perform any action on any resource. Since this role can be assumed by our compromised user, we have full access to the target environment.

## Wrapping Up
In this blog post, we talked about different policies in aws and covered some dangerous permissions that could lead to privilege escalation. 

That's it for now folks. See you in the next post.

### References
This blog post could not have been possible without the amazing work of multiple peeps. Kudos to all the original researchers!
- [https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [https://bishopfox.com/blog/privilege-escalation-in-aws](https://bishopfox.com/blog/privilege-escalation-in-aws)
- [https://github.com/BishopFox/iam-vulnerable](https://github.com/BishopFox/iam-vulnerable)