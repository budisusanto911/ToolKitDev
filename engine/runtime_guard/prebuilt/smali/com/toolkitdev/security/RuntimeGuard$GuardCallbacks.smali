.class public final Lcom/toolkitdev/security/RuntimeGuard$GuardCallbacks;
.super Ljava/lang/Object;
.source "RuntimeGuard.java"

# interfaces
.implements Landroid/app/Application$ActivityLifecycleCallbacks;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/toolkitdev/security/RuntimeGuard;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "GuardCallbacks"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 945
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    .line 948
    const/4 p2, 0x0

    invoke-static {p1, p2}, Lcom/toolkitdev/security/RuntimeGuard;->access$200(Landroid/content/Context;Z)V

    .line 949
    return-void
.end method

.method public onActivityDestroyed(Landroid/app/Activity;)V
    .locals 0

    .line 971
    return-void
.end method

.method public onActivityPaused(Landroid/app/Activity;)V
    .locals 0

    .line 962
    return-void
.end method

.method public onActivityResumed(Landroid/app/Activity;)V
    .locals 1

    .line 958
    const/4 v0, 0x1

    invoke-static {p1, v0}, Lcom/toolkitdev/security/RuntimeGuard;->access$200(Landroid/content/Context;Z)V

    .line 959
    return-void
.end method

.method public onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    .line 968
    return-void
.end method

.method public onActivityStarted(Landroid/app/Activity;)V
    .locals 1

    .line 953
    const/4 v0, 0x0

    invoke-static {p1, v0}, Lcom/toolkitdev/security/RuntimeGuard;->access$200(Landroid/content/Context;Z)V

    .line 954
    return-void
.end method

.method public onActivityStopped(Landroid/app/Activity;)V
    .locals 0

    .line 965
    return-void
.end method
