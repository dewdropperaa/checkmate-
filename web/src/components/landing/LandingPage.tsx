import { CTA } from "./CTA";
import { FAQ } from "./FAQ";
import { Features } from "./Features";
import { Hero } from "./Hero";
import { HowItWorks } from "./HowItWorks";
import { Marquee } from "./Marquee";
import { Pricing } from "./Pricing";
import { SiteFooter } from "./SiteFooter";
import { SiteHeader } from "./SiteHeader";
import { SocialProof } from "./SocialProof";
import { Testimonials } from "./Testimonials";

export function LandingPage() {
  return (
    <>
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <SiteHeader />
      <main id="main">
        <Hero />
        <Marquee />
        <SocialProof />
        <HowItWorks />
        <Features />
        <Testimonials />
        <Pricing />
        <CTA />
        <FAQ />
      </main>
      <SiteFooter />
    </>
  );
}
