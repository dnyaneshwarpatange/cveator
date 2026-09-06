from app.providers.razorpay.config import RazorpaySettings
from app.providers.razorpay.razorpay_payment_provider import RazorpayPaymentProvider


def create_payment_provider() -> RazorpayPaymentProvider:
    return RazorpayPaymentProvider(RazorpaySettings())
