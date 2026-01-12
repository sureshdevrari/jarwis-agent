// CapabilitiesGrid.jsx
// Feature capabilities grid for solution pages

const CapabilitiesGrid = ({ 
  title = "Comprehensive Security Coverage",
  subtitle = "Enterprise-grade scanning powered by AI",
  capabilities = [],
  scanType = 'web'
}) => {
  const accentColors = {
    web: {
      iconBg: 'bg-cyan-500/20',
      iconText: 'text-cyan-400',
      hoverBorder: 'hover:border-cyan-500/30',
      hoverShadow: 'hover:shadow-cyan-500/10'
    },
    mobile: {
      iconBg: 'bg-purple-500/20',
      iconText: 'text-purple-400',
      hoverBorder: 'hover:border-purple-500/30',
      hoverShadow: 'hover:shadow-purple-500/10'
    },
    network: {
      iconBg: 'bg-green-500/20',
      iconText: 'text-green-400',
      hoverBorder: 'hover:border-green-500/30',
      hoverShadow: 'hover:shadow-green-500/10'
    },
    cloud: {
      iconBg: 'bg-orange-500/20',
      iconText: 'text-orange-400',
      hoverBorder: 'hover:border-orange-500/30',
      hoverShadow: 'hover:shadow-orange-500/10'
    },
    sast: {
      iconBg: 'bg-red-500/20',
      iconText: 'text-red-400',
      hoverBorder: 'hover:border-red-500/30',
      hoverShadow: 'hover:shadow-red-500/10'
    }
  };

  const colors = accentColors[scanType];

  return (
    <section className="relative py-20 lg:py-32">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-16">
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-white mb-4">
            {title}
          </h2>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            {subtitle}
          </p>
        </div>

        {/* Capabilities Grid */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          {capabilities.map((capability, index) => (
            <div
              key={index}
              className={`solution-feature-card group ${colors.hoverBorder} ${colors.hoverShadow}`}
              style={{ animationDelay: `${index * 100}ms` }}
            >
              {/* Icon */}
              <div className={`w-12 h-12 rounded-xl ${colors.iconBg} ${colors.iconText} flex items-center justify-center mb-4 transition-transform group-hover:scale-110`}>
                {capability.icon || (
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                )}
              </div>

              {/* Content */}
              <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-cyan-300 transition-colors">
                {capability.title}
              </h3>
              <p className="text-sm text-gray-400 leading-relaxed">
                {capability.description}
              </p>

              {/* Tags */}
              {capability.tags && (
                <div className="flex flex-wrap gap-2 mt-4">
                  {capability.tags.map((tag, tagIndex) => (
                    <span
                      key={tagIndex}
                      className="px-2 py-1 text-xs rounded-md bg-white/5 text-gray-400 border border-white/10"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default CapabilitiesGrid;
