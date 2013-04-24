package ie.dcu.collir24;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.IOFileFilter;
import org.apache.commons.io.filefilter.RegexFileFilter;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.IllegalNameException;
import org.jdom2.JDOMException;
import org.jdom2.Namespace;
import org.jdom2.filter.Filters;
import org.jdom2.input.SAXBuilder;
import org.jdom2.input.sax.XMLReaders;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.xpath.XPathExpression;
import org.jdom2.xpath.XPathFactory;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;

public class MavenDependencies {
	private static final IOFileFilter NAME_FILTER = new RegexFileFilter(
			"^.*\\.(pom)$");
	private static final XPathFactory XPFAC = XPathFactory.instance();
	private static final SAXBuilder BUILDER = new SAXBuilder(
			XMLReaders.NONVALIDATING);
	private static final Multimap<String, String> map = HashMultimap.create();
	private static final Logger LOGGER = Logger
			.getLogger(MavenDependencies.class.getName());

	/**
	 * @param args
	 * @throws IOException
	 * @throws JDOMException
	 */
	public static void main(String[] args) {
		Collection<File> files = FileUtils.listFiles(new File(
				"/Volumes/Maven/maven2/"), NAME_FILTER,
				TrueFileFilter.INSTANCE);
		for (File file : files) {
			try {
				getFileDependencies(file);
			} catch (IllegalNameException e) {
				LOGGER.log(Level.WARNING,
						"Problem with: " + file.getAbsolutePath(), e);
			} catch (JDOMException e) {
				LOGGER.log(Level.WARNING,
						"Problem with: " + file.getAbsolutePath(), e);
			} catch (IOException e) {
				LOGGER.log(Level.WARNING,
						"Problem with: " + file.getAbsolutePath(), e);
			}
		}
		writeOutput(map);
	}

	private static void getFileDependencies(File file) throws JDOMException,
			IOException {
		Document doc = BUILDER.build(new InputStreamReader(new FileInputStream(
				file), "UTF-8"));
		Set<String> dependsOn = new LinkedHashSet<String>();

		for (Element dependency : getDependencies(doc)) {
			Namespace ns = dependency.getNamespace();
			Element scope = dependency.getChild("scope", ns);
			if (scope == null || scope.getText().equals("compile")) {
				String groupId = dependency.getChildTextTrim("groupId", ns);
				String artifactId = dependency.getChildTextTrim("artifactId",
						ns);
				dependsOn.add(getDependencyLabel(groupId, artifactId));
			}
		}
		if (!dependsOn.isEmpty()) {
			String moduleName = getModuleName(doc);
			map.putAll(moduleName, dependsOn);
		}
	}

	private static String getModuleName(Document doc) {
		Element project = doc.getRootElement();
		Namespace ns = project.getNamespace();
		String groupId = project.getChildTextTrim("groupId", ns);
		String artifactId = project.getChildTextTrim("artifactId", ns);
		if (groupId == null || groupId.isEmpty()) {
			Element parent = project.getChild("parent", ns);
			if (parent == null) {
				// must be maven3
				groupId = project.getChildTextTrim("name", ns);
				artifactId = project.getChildTextTrim("id", ns);
			} else {
				groupId = parent.getChildTextTrim("groupId", ns);	
			}	
		}
		
		return getDependencyLabel(groupId, artifactId);
	}

	private static String getDependencyLabel(String groupId, String artifactId) {
		StringBuilder sb = new StringBuilder();
		return sb.append(groupId).append(":").append(artifactId).toString()
				.intern();
	}

	@SuppressWarnings("unchecked")
	private static List<Element> getDependencies(Document doc)
			throws JDOMException, IOException {
		Element project = doc.getRootElement();
		Namespace ns = project.getNamespace();

		XPathExpression<Element> expression;
		if (ns.getURI() == null || ns.getURI().isEmpty()) {
			expression = XPFAC.compile("/project/dependencies/dependency",
					Filters.element());
		} else {
			expression = XPFAC.compile(
					"/mvn:project/mvn:dependencies/mvn:dependency",
					Filters.element(), Collections.EMPTY_MAP,
					Namespace.getNamespace("mvn", ns.getURI()));
		}
		return expression.evaluate(doc);
	}

	private static void writeOutput(Multimap<String, String> dependencies) {
		Writer writer = null;
		try {
			writer = new BufferedWriter(new FileWriter("perms.gexf"));
			outputDependencies(dependencies, writer);
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "Problem creating writer", e);
		} finally {
			if (writer != null) {
				try {
					writer.flush();
					writer.close();
				} catch (IOException e) {
					LOGGER.log(Level.SEVERE, "Problem closing writer", e);
				}
			}
		}
	}

	private static void outputDependencies(
			Multimap<String, String> dependencies, Writer writer) {
		XMLOutputter xmlOut = new XMLOutputter(Format.getCompactFormat());
		Element root = new Element("gexf", "http://www.gexf.net/1.2draft");
		root.setAttribute("version", "1.2");
		Element graph = new Element("graph", "http://www.gexf.net/1.2draft");
		Element attributes = new Element("attributes",
				"http://www.gexf.net/1.2draft");
		Element nodes = new Element("nodes", "http://www.gexf.net/1.2draft");
		Element edges = new Element("edges", "http://www.gexf.net/1.2draft");
		attributes.setAttribute("class", "node");
		Element permissionAttribute = new Element("attribute",
				"http://www.gexf.net/1.2draft");
		permissionAttribute.setAttribute("id", "0");
		permissionAttribute.setAttribute("title", "type");
		permissionAttribute.setAttribute("type", "string");
		Element defaultAttributeElement = new Element("default",
				"http://www.gexf.net/1.2draft");
		defaultAttributeElement.setText("module");
		permissionAttribute.addContent(defaultAttributeElement);
		attributes.addContent(permissionAttribute);
		graph.setAttribute("defaultedgetype", "directed");
		root.addContent(graph);
		graph.addContent(attributes);
		graph.addContent(nodes);
		graph.addContent(edges);

		Map<String, Integer> nodeIdMap = addNodes(dependencies, nodes);
		addEdges(dependencies, edges, nodeIdMap);
		try {
			xmlOut.output(root, writer);
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "Problem writing doc", e);
		}
	}

	private static void addEdges(Multimap<String, String> dependencies,
			Element edges, Map<String, Integer> nodeIdMap) {
		int edgeId = Integer.MAX_VALUE;
		for (String module : dependencies.keySet()) {
			String moduleId = nodeIdMap.get(module).toString();
			Collection<String> moduleDeps = dependencies.get(module);
			for (String dependsOn : moduleDeps) {
				Element permissionLink = new Element("edge",
						"http://www.gexf.net/1.2draft");
				permissionLink.setAttribute("id", Integer.toString(edgeId));
				permissionLink.setAttribute("source", moduleId);
				permissionLink.setAttribute("target", nodeIdMap.get(dependsOn)
						.toString());
				edges.addContent(permissionLink);
				edgeId--;
			}
		}
	}

	private static Map<String, Integer> addNodes(
			Multimap<String, String> dependencies, Element nodes) {
		Map<String, Integer> nodeIdMap = getNodeIds(dependencies);
		for (Map.Entry<String, Integer> node : nodeIdMap.entrySet()) {
			Element moduleElement = new Element("node",
					"http://www.gexf.net/1.2draft");
			moduleElement.setAttribute("id", node.getValue().toString());
			moduleElement.setAttribute("label", node.getKey());
			nodes.addContent(moduleElement);
		}
		return nodeIdMap;
	}

	private static Map<String, Integer> getNodeIds(
			Multimap<String, String> dependencies) {
		Map<String, Integer> map = new HashMap<String, Integer>();
		int i = 0;
		for (String s : dependencies.values()) {
			map.put(s, i);
			i++;
		}
		for (String s : dependencies.keySet()) {
			map.put(s, i);
			i++;
		}
		return map;
	}

}
