.class Lcom/toolkitdev/security/RuntimeGuard$4;
.super Ljava/lang/Object;
.source "RuntimeGuard.java"

# interfaces
.implements Landroid/content/DialogInterface$OnDismissListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/toolkitdev/security/RuntimeGuard;->enforceSecurity(Landroid/content/Context;Z)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic val$activity:Landroid/app/Activity;


# direct methods
.method constructor <init>(Landroid/app/Activity;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 879
    iput-object p1, p0, Lcom/toolkitdev/security/RuntimeGuard$4;->val$activity:Landroid/app/Activity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onDismiss(Landroid/content/DialogInterface;)V
    .locals 0

    .line 882
    iget-object p1, p0, Lcom/toolkitdev/security/RuntimeGuard$4;->val$activity:Landroid/app/Activity;

    invoke-static {p1}, Lcom/toolkitdev/security/RuntimeGuard;->access$100(Landroid/app/Activity;)V

    .line 883
    return-void
.end method
