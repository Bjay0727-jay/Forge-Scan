import { useState, useMemo, type ReactNode } from 'react';
import { Search, ExternalLink } from 'lucide-react';
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
} from '@/components/ui/tooltip';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';

interface FederalTerm {
  abbreviation: string;
  fullName: string;
  description: string;
  referenceUrl?: string;
}

const FEDERAL_TERMS: Record<string, FederalTerm> = {
  SSP: {
    abbreviation: 'SSP',
    fullName: 'System Security Plan',
    description:
      'A formal document that describes the security controls in place or planned for an information system. It outlines the system boundary, environment, and how each security requirement is satisfied.',
    referenceUrl: 'https://csrc.nist.gov/glossary/term/system_security_plan',
  },
  ATO: {
    abbreviation: 'ATO',
    fullName: 'Authority to Operate',
    description:
      'A formal declaration by a designated authorizing official that an information system is approved to operate at an acceptable level of risk. It is granted after a comprehensive security assessment.',
    referenceUrl: 'https://csrc.nist.gov/glossary/term/authorization_to_operate',
  },
  'POA&M': {
    abbreviation: 'POA&M',
    fullName: 'Plan of Action and Milestones',
    description:
      'A document that identifies tasks needing to be accomplished to resolve security weaknesses. It details resources required, milestones for correcting deficiencies, and scheduled completion dates.',
    referenceUrl: 'https://csrc.nist.gov/glossary/term/plan_of_action_and_milestones',
  },
  ISSO: {
    abbreviation: 'ISSO',
    fullName: 'Information System Security Officer',
    description:
      'An individual responsible for ensuring the operational security posture of an information system. The ISSO serves as the principal advisor on all security matters related to a specific system.',
  },
  'FIPS 199': {
    abbreviation: 'FIPS 199',
    fullName: 'Federal Information Processing Standard 199',
    description:
      'A mandatory federal standard that establishes security categories for information and information systems based on potential impact levels (low, moderate, high) to organizations or individuals.',
    referenceUrl: 'https://csrc.nist.gov/publications/detail/fips/199/final',
  },
  OSCAL: {
    abbreviation: 'OSCAL',
    fullName: 'Open Security Controls Assessment Language',
    description:
      'A NIST-developed set of standardized, machine-readable formats for documenting and exchanging security control information. It enables automation of security assessment and authorization processes.',
    referenceUrl: 'https://pages.nist.gov/OSCAL/',
  },
  FedRAMP: {
    abbreviation: 'FedRAMP',
    fullName: 'Federal Risk and Authorization Management Program',
    description:
      'A government-wide program that provides a standardized approach to security authorizations for cloud service offerings. It promotes the adoption of secure cloud services across the federal government.',
    referenceUrl: 'https://www.fedramp.gov/',
  },
  RMF: {
    abbreviation: 'RMF',
    fullName: 'Risk Management Framework',
    description:
      'A structured process developed by NIST that integrates security and risk management activities into the system development life cycle. It provides a disciplined approach for managing organizational risk.',
    referenceUrl: 'https://csrc.nist.gov/projects/risk-management/about-rmf',
  },
  FISMA: {
    abbreviation: 'FISMA',
    fullName: 'Federal Information Security Modernization Act',
    description:
      'Federal legislation that requires federal agencies to develop, document, and implement information security programs. It establishes a framework for protecting government information and operations.',
    referenceUrl: 'https://csrc.nist.gov/topics/laws-and-regulations/laws/fisma',
  },
  'NIST SP 800-53': {
    abbreviation: 'NIST SP 800-53',
    fullName: 'NIST Special Publication 800-53',
    description:
      'A catalog of security and privacy controls for federal information systems and organizations. It provides a comprehensive set of safeguards to protect against a diverse set of threats.',
    referenceUrl: 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
  },
  STIG: {
    abbreviation: 'STIG',
    fullName: 'Security Technical Implementation Guide',
    description:
      'A configuration standard published by DISA consisting of technical guidance for hardening information systems and software. STIGs contain technical rules for securing specific products.',
    referenceUrl: 'https://public.cyber.mil/stigs/',
  },
  'CIS Benchmarks': {
    abbreviation: 'CIS Benchmarks',
    fullName: 'Center for Internet Security Benchmarks',
    description:
      'Consensus-based best-practice security configuration guides developed by the Center for Internet Security. They provide prescriptive guidance for establishing a secure baseline configuration.',
    referenceUrl: 'https://www.cisecurity.org/cis-benchmarks',
  },
};

// Aliases so partial matches in the page text can resolve to a glossary entry
const TERM_ALIASES: Record<string, string> = {
  'NIST 800-53': 'NIST SP 800-53',
  'NIST800-53': 'NIST SP 800-53',
  'SP 800-53': 'NIST SP 800-53',
  CIS: 'CIS Benchmarks',
  POAM: 'POA&M',
};

function resolveTerm(term: string): FederalTerm | undefined {
  return FEDERAL_TERMS[term] ?? FEDERAL_TERMS[TERM_ALIASES[term]];
}

// ---------------------------------------------------------------------------
// FederalTermTooltip
// ---------------------------------------------------------------------------

interface FederalTermTooltipProps {
  term: string;
  children: ReactNode;
}

export function FederalTermTooltip({ term, children }: FederalTermTooltipProps) {
  const entry = resolveTerm(term);

  if (!entry) {
    return <>{children}</>;
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="underline decoration-dotted decoration-[hsl(210_40%_50%)] underline-offset-4 cursor-help">
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        <p className="font-semibold text-white">{entry.abbreviation}</p>
        <p className="text-xs text-[hsl(210_40%_70%)] mb-1">{entry.fullName}</p>
        <p className="text-xs leading-relaxed">{entry.description}</p>
        {entry.referenceUrl && (
          <a
            href={entry.referenceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 mt-1"
            onClick={(e) => e.stopPropagation()}
          >
            Reference <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </TooltipContent>
    </Tooltip>
  );
}

// ---------------------------------------------------------------------------
// FederalTermsGlossary
// ---------------------------------------------------------------------------

interface FederalTermsGlossaryProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function FederalTermsGlossary({ open, onOpenChange }: FederalTermsGlossaryProps) {
  const [search, setSearch] = useState('');

  const filteredTerms = useMemo(() => {
    const query = search.toLowerCase().trim();
    if (!query) return Object.values(FEDERAL_TERMS);
    return Object.values(FEDERAL_TERMS).filter(
      (t) =>
        t.abbreviation.toLowerCase().includes(query) ||
        t.fullName.toLowerCase().includes(query) ||
        t.description.toLowerCase().includes(query)
    );
  }, [search]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>Federal Security Terms Glossary</DialogTitle>
          <DialogDescription>
            Reference guide for common federal security and compliance terminology.
          </DialogDescription>
        </DialogHeader>

        {/* Search input */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[hsl(210_20%_50%)]" />
          <input
            type="text"
            placeholder="Search terms..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-md border border-[hsl(213_30%_28%)] bg-[hsl(213_50%_12%)] pl-9 pr-3 py-2 text-sm text-white placeholder:text-[hsl(210_20%_50%)] focus:outline-none focus:ring-2 focus:ring-primary"
          />
        </div>

        {/* Terms list */}
        <div className="flex-1 overflow-y-auto -mx-6 px-6 space-y-3 min-h-0">
          {filteredTerms.length === 0 ? (
            <p className="text-sm text-[hsl(210_20%_50%)] text-center py-8">
              No terms match your search.
            </p>
          ) : (
            filteredTerms.map((term) => (
              <div
                key={term.abbreviation}
                className="rounded-lg border border-[hsl(213_30%_24%)] bg-[hsl(213_50%_12%)] p-4"
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <p className="font-semibold text-white">{term.abbreviation}</p>
                    <p className="text-xs text-[hsl(210_40%_70%)]">{term.fullName}</p>
                  </div>
                  {term.referenceUrl && (
                    <a
                      href={term.referenceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="shrink-0 text-[hsl(210_40%_70%)] hover:text-white transition-colors"
                    >
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  )}
                </div>
                <p className="text-sm text-[hsl(213_20%_65%)] mt-2 leading-relaxed">
                  {term.description}
                </p>
              </div>
            ))
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
